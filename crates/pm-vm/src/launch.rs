//! Starting the machine with a program a [`Launcher`] names, instead of starting
//! QEMU directly.
//!
//! A launcher is asked once per boot, with the machine already laid out in its
//! directory: the initramfs, a private copy of the kernel, and the status socket pm
//! listens on. It answers with a program, its arguments and any files to write
//! next to those - a domain definition, say - or with nothing, which leaves the
//! machine to QEMU. pm then holds the program to three rules, and that is the whole
//! contract:
//!
//! * **It lives exactly as long as the machine.** pm waits for it to exit and
//!   counts the machine as stopped when it does, so a program that starts a
//!   machine and returns would stop the wait early, and one that outlives its
//!   machine would hold `pm run` up.
//! * **It owns the console.** It gets pm's terminal when pm has one, and otherwise
//!   a pseudo-terminal pm copies to and from its own stdin and stdout, so a
//!   program that insists on a terminal works under a pipe too.
//! * **The guest's second serial port goes to the status socket.** Init reports
//!   how the entrypoint exited there, as it does under QEMU started by pm, and
//!   that report, not the program's exit status, is what `pm run` returns.
//!
//! The program may run QEMU as another user, as libvirt's system daemon does. So
//! the directory is made searchable but not listable, and every file in it is
//! private to its owner: whoever runs QEMU has to be handed each file it opens,
//! which is what libvirt does for the kernel, the initramfs and the sockets. And
//! the program is told to stop (`SIGTERM`) if pm dies first, so a machine whose
//! caller went away does not keep running.

use std::{
    fs::{self, File, OpenOptions, Permissions},
    io::{self, ErrorKind, IsTerminal, Read, Write},
    os::{
        fd::{AsFd, OwnedFd},
        unix::{fs::PermissionsExt, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
};

use hakoniwa::ExitStatus;
use miette::{IntoDiagnostic, WrapErr, miette};
use nix::{
    errno::Errno,
    poll::{PollFd, PollFlags, PollTimeout, poll},
    pty::openpty,
    sys::{
        prctl,
        signal::Signal,
        termios::{SetArg, cfmakeraw, tcgetattr, tcsetattr},
    },
    unistd::setsid,
};
use tracing::{debug, info, warn};

use pm_workspace::HostChild;

use crate::{Boot, Prepared, find_on_path, no_report, parse_report, read_report};

/// The machine as a [`Launcher`] sees it. Every path is absolute and already
/// exists, except the files the launcher itself asks for.
#[derive(Debug, Clone, Copy)]
pub struct Machine<'a> {
    /// A name unique on the host, `pm-vm-` and random characters: the machine's
    /// directory's own name.
    pub name: &'a str,
    /// One line saying what runs in it, for a list of machines.
    pub title: &'a str,
    /// The machine's directory, where the launcher's files are written.
    pub directory: &'a Path,
    /// The package's kernel image.
    pub kernel: &'a Path,
    /// The initramfs pm assembled: the package, its libraries and pm's init.
    pub initramfs: &'a Path,
    /// The whole kernel command line, pm's parameters included.
    pub cmdline: &'a str,
    /// Memory the guest needs, in MiB.
    pub memory_mib: u64,
    /// Virtual CPUs.
    pub cpus: usize,
    /// Whether this process can use KVM. A launcher whose machines run elsewhere
    /// may know better.
    pub kvm: bool,
    /// The socket the guest's second serial port has to reach, as a client.
    pub status_socket: &'a Path,
}

/// How a [`Launcher`] starts a machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    /// Who answered, for the log: a plugin's name.
    pub by: String,
    /// The program: a name found on `PATH`, or a path.
    pub program: PathBuf,
    /// Its arguments.
    pub args: Vec<String>,
    /// Files to write into the machine's directory before it starts.
    pub files: Vec<LaunchFile>,
}

/// A file a [`Launch`] wants in the machine's directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchFile {
    /// A plain file name: letters, digits, `.`, `_` and `-`, not starting with `.`.
    pub name: String,
    /// What it holds.
    pub contents: Vec<u8>,
}

/// Something that may start a machine instead of pm starting QEMU.
pub trait Launcher {
    /// How to start `machine`, or `None` to leave it to pm.
    ///
    /// # Errors
    ///
    /// A launcher that cannot answer at all. pm fails the boot rather than quietly
    /// starting QEMU in its place, because the launcher was installed to be used.
    fn launch(&self, machine: &Machine<'_>) -> miette::Result<Option<Launch>>;
}

/// Lay the machine out for a program that may run as another user, and ask
/// `launcher` how to start it.
pub(crate) fn ask(
    launcher: &dyn Launcher,
    prepared: &Prepared,
    request: &Boot<'_>,
) -> miette::Result<Option<Launch>> {
    let directory = prepared.scratch.path();
    // Searchable, so a name pm hands out opens, but not listable.
    fs::set_permissions(directory, Permissions::from_mode(0o711))
        .into_diagnostic()
        .wrap_err_with(|| format!("cannot open {} to a launcher", directory.display()))?;
    // The kernel is in the extracted package, whose directory stays private; a
    // copy here is reachable.
    let kernel = directory.join("kernel");
    fs::copy(&prepared.image, &kernel)
        .into_diagnostic()
        .wrap_err("cannot copy the kernel image for a launcher")?;
    for file in [&kernel, &prepared.initramfs] {
        fs::set_permissions(file, Permissions::from_mode(0o600))
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot make {} private", file.display()))?;
    }
    let name = machine_name(directory);
    let title = format!("pm run: {}", request.entrypoint.display());
    let machine = Machine {
        name: &name,
        title: &title,
        directory,
        kernel: &kernel,
        initramfs: &prepared.initramfs,
        cmdline: &prepared.cmdline,
        memory_mib: prepared.memory_mib,
        cpus: prepared.cpus,
        kvm: kvm_usable(),
        status_socket: &prepared.status_socket,
    };
    launcher.launch(&machine)
}

/// Write the launch's files, run its program, and return how the entrypoint
/// exited once the program has.
pub(crate) fn run(launch: Launch, prepared: Prepared) -> miette::Result<ExitStatus> {
    let directory = prepared.scratch.path();
    for file in &launch.files {
        write_file(directory, file)?;
    }
    let program = resolve(&launch)?;
    let mut command = Command::new(&program);
    command.args(&launch.args).current_dir(directory);

    // A terminal of pm's own goes to the program as it is. Without one the
    // program gets a pseudo-terminal, whose other end pm copies.
    let terminal = io::stdin().is_terminal() && io::stdout().is_terminal();
    let pty = if terminal {
        None
    } else {
        let pty = openpty(None, None)
            .into_diagnostic()
            .wrap_err("cannot open a pseudo-terminal for the launcher")?;
        // Raw, so the bytes the guest writes arrive as written, and the program
        // sets the line discipline it wants itself.
        if let Ok(mut settings) = tcgetattr(&pty.slave) {
            cfmakeraw(&mut settings);
            let _ = tcsetattr(&pty.slave, SetArg::TCSANOW, &settings);
        }
        let slave = File::from(pty.slave);
        command
            .stdin(stdio(&slave)?)
            .stdout(stdio(&slave)?)
            .stderr(stdio(&slave)?);
        Some(File::from(pty.master))
    };
    let controlling = pty.is_some();
    // SAFETY: only async-signal-safe system calls run between fork and exec.
    unsafe {
        command.pre_exec(move || {
            // Stop when pm does, rather than keep a machine nobody waits for.
            prctl::set_pdeathsig(Signal::SIGTERM)?;
            if controlling {
                // A session of its own, with the pseudo-terminal on fd 0 as its
                // controlling terminal, which a console program checks for.
                setsid()?;
                if nix::libc::ioctl(0, nix::libc::TIOCSCTTY, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    debug!(?command, by = %launch.by, "starting the launcher");
    info!(
        by = %launch.by,
        program = %program.display(),
        memory_mib = prepared.memory_mib,
        "booting the package's own kernel in a virtual machine"
    );
    let label = program.display().to_string();
    let child = command
        .spawn()
        .into_diagnostic()
        .wrap_err_with(|| format!("cannot start {label}"))?;
    // The slave end now belongs to the child alone, so the master reads EIO once
    // the child has exited and closed it.
    drop(command);
    let child = HostChild::new(child, label.clone());

    let done = AtomicBool::new(false);
    let (exited, report) = thread::scope(|scope| {
        let status = scope.spawn(|| read_report(&prepared.status, &done));
        if let Some(master) = &pty {
            scope.spawn(|| copy_out(master));
            scope.spawn(|| copy_in(master, &done));
        }
        let exited = child.wait();
        done.store(true, Ordering::Release);
        (exited, status.join().unwrap_or_default())
    });
    let exited = exited?;
    let status = parse_report(&report);
    if status.is_none() && !exited.success() {
        return Err(miette!(
            "{label} exited with {exited} before the guest reported anything"
        ));
    }
    Ok(status.unwrap_or_else(no_report))
}

/// Another handle on `file`, for one of the child's standard streams.
fn stdio(file: &File) -> miette::Result<Stdio> {
    let fd: OwnedFd = file
        .try_clone()
        .into_diagnostic()
        .wrap_err("cannot hand the pseudo-terminal to the launcher")?
        .into();
    Ok(Stdio::from(fd))
}

/// Copy what the program writes to its terminal to stdout, until it has exited.
fn copy_out(master: &File) {
    let mut stdout = io::stdout().lock();
    let mut buffer = [0u8; 4096];
    let mut reader = master;
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                if stdout
                    .write_all(&buffer[..count])
                    .and_then(|()| stdout.flush())
                    .is_err()
                {
                    break;
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            // EIO: every handle on the other end is closed, so the program is gone.
            Err(_) => break,
        }
    }
}

/// Copy stdin to the program's terminal until stdin ends or the program exits.
///
/// Stdin is polled rather than read outright, so this returns once the machine
/// has stopped even though nobody typed anything.
fn copy_in(master: &File, done: &AtomicBool) {
    let stdin = io::stdin();
    let mut buffer = [0u8; 1024];
    let mut writer = master;
    while !done.load(Ordering::Acquire) {
        let mut fds = [PollFd::new(stdin.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, PollTimeout::from(50u8)) {
            Ok(0) | Err(Errno::EINTR) => continue,
            Ok(_) => {}
            Err(error) => {
                warn!(%error, "cannot wait for input");
                return;
            }
        }
        match stdin.lock().read(&mut buffer) {
            // End of input. The terminal stays open, so the guest's output keeps
            // coming.
            Ok(0) => return,
            Ok(count) => {
                if writer.write_all(&buffer[..count]).is_err() {
                    return;
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => {
                warn!(%error, "cannot read stdin");
                return;
            }
        }
    }
}

/// The launch's program as a path: as given when it has a `/`, else from `PATH`.
fn resolve(launch: &Launch) -> miette::Result<PathBuf> {
    if launch.program.components().count() > 1 {
        return Ok(launch.program.clone());
    }
    let name = launch.program.to_string_lossy();
    find_on_path(&name).ok_or_else(|| {
        miette!(
            help = "install it, or boot with QEMU directly: `pm run --qemu`",
            "{} starts this machine with {name}, which is not on PATH",
            launch.by
        )
    })
}

/// Write `file` into `directory`, private to its owner, refusing a name that is
/// not plain or that is already taken by the machine's own files.
///
/// Public for `pm machine`, whose steps write their files the same way.
///
/// # Errors
///
/// The name is not plain, a file of that name exists already, or it cannot be
/// written.
pub fn write_file(directory: &Path, file: &LaunchFile) -> miette::Result<()> {
    let plain = !file.name.is_empty()
        && !file.name.starts_with('.')
        && file
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !plain {
        return Err(miette!(
            "a launcher asked for the file `{}`, which is not a plain file name",
            file.name
        ));
    }
    let path = directory.join(&file.name);
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "cannot write the launcher's {}; the machine's own files cannot be replaced",
                file.name
            )
        })?;
    out.set_permissions(Permissions::from_mode(0o600))
        .into_diagnostic()?;
    out.write_all(&file.contents)
        .into_diagnostic()
        .wrap_err_with(|| format!("cannot write {}", path.display()))
}

/// The machine directory's own random name, kept to the characters a machine
/// name takes anywhere, and starting with `pm-`.
fn machine_name(directory: &Path) -> String {
    let name: String = directory
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .collect();
    if name.starts_with("pm-") {
        name
    } else {
        format!("pm-{name}")
    }
}

/// Whether `/dev/kvm` opens for this process.
fn kvm_usable() -> bool {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

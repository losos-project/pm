//! Packages that ship their own kernel, and booting them in a virtual machine.
//!
//! A recipe can declare `kernel = kernel(image = "boot/vmlinuz")`. The build checks
//! that its install steps staged a Linux kernel image at that package-relative
//! path, and the package metadata records it as a [`Kernel`]. `pm run` then boots
//! that kernel in a QEMU virtual machine and runs the chosen entrypoint as the
//! guest's only program, instead of running it in the namespace jail on the host's
//! kernel. `pm run --host-kernel` keeps the jail.
//!
//! # Launchers
//!
//! By default pm starts QEMU itself. A [`Launcher`] can start the machine instead -
//! pm's plugins are one, and the `libvirt` plugin uses that to hand the machine to
//! libvirt - and is asked first: pm writes the initramfs, copies the kernel next to
//! it, describes the machine ([`Machine`]) and runs whatever program the launcher
//! names, with the files it asks for written into the machine's directory. The
//! program owns the console and lives exactly as long as the machine. When no
//! launcher answers, pm starts QEMU as before. See [`launch`].
//!
//! # What the guest sees
//!
//! The guest's root filesystem is an initramfs pm assembles for each run ([`boot`]):
//!
//! * the extracted package at `/pkg`, minus the kernel image itself;
//! * the host's loader and shared libraries the package's binaries link, at their
//!   host paths, taken only from the system directories the run jail mirrors
//!   ([`closure`]);
//! * pm's guest [`init`](guest) - `pm-vm-init` from beside `pm`, or `pm` itself -
//!   with its own libraries;
//! * `/dev/console`, `/dev/null` and the two serial ports, and empty `/proc`,
//!   `/sys` and `/tmp` that init mounts.
//!
//! Nothing else from the host is there: no `/etc`, no `/home`, no host `/tmp`. The
//! machine has no network device and no disk. The landlock profile a package
//! records is not applied inside the guest, because there is nothing outside the
//! package and its libraries for it to deny; the VM boundary replaces it.
//!
//! # What this does not do
//!
//! * **Other architectures.** Only x86-64 hosts boot a package kernel today, with
//!   two 16550 serial ports on QEMU's `pc` machine. Other hosts refuse with an
//!   error; `--host-kernel` still runs the package.
//! * **Network.** The guest has no NIC, and `--network` is refused rather than
//!   silently ignored.
//! * **Auditing.** `--audit` traces a host process with `ptrace`, which cannot see
//!   into a VM, so it is refused too.
//! * **Confining QEMU.** Started by pm, QEMU runs as the calling user, outside any
//!   jail; a launcher may run it elsewhere, as libvirt's system daemon does. The
//!   package's code only ever runs inside the guest.
//! * **Trusting the exit status.** Init reports how the entrypoint exited on the
//!   second serial port. Code running in the guest could write to that port too, so
//!   the status is the package's claim about itself, not a measurement.
//!
//! # What the kernel needs
//!
//! An initramfs, an 8250/16550 serial console and ELF binaries for the host's
//! architecture, all built in rather than as modules: nothing in the guest loads
//! modules. Distribution "generic" and "virtual" kernels have all three.

/// Finding the host files a program needs to start in the guest.
pub mod closure;
/// Writing the `newc` cpio archive the guest boots from.
pub mod cpio;
/// pm as the guest's init.
pub mod guest;
/// Starting the machine with a program a [`Launcher`] names.
pub mod launch;

pub use launch::{Launch, LaunchFile, Launcher, Machine};

use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{BufWriter, ErrorKind, Read},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

use hakoniwa::ExitStatus;
use miette::{IntoDiagnostic, WrapErr, miette};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use walkdir::WalkDir;

use pm_workspace::{HostChild, Workspace};

use cpio::Newc;

/// Where the extracted package is in the guest.
pub const GUEST_PACKAGE_ROOT: &str = "/pkg";

/// The file init reads what to run from.
const GUEST_CONFIG: &str = "/pm-vm.json";

/// The serial port init reports the entrypoint's exit on. `ttyS0` is the console.
const STATUS_PORT: &str = "/dev/ttyS1";

/// The `PATH` the entrypoint starts with, which is also where `#!/usr/bin/env
/// program` scripts find `program` ([`closure`]).
pub const GUEST_PATH: &str = "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin";

/// The most of init's report pm keeps. A report is one short line; the guest can
/// write as much as it likes to the port, and everything past this is discarded.
const MAX_REPORT: usize = 4096;

/// `e_machine` of an x86-64 ELF file.
const EM_X86_64: u16 = 62;

/// Kernel parameters pm sets itself and a package cannot: they decide which
/// program runs as init.
const RESERVED_PARAMETERS: [&str; 2] = ["init", "rdinit"];

/// The longest extra command line a package may ask for.
///
/// x86's boot protocol allows 2048 bytes in all, and pm's own parameters need a
/// share of that.
const MAX_CMDLINE: usize = 1024;

/// Memory the guest gets on top of three times the initramfs: the kernel holds it
/// once as the archive and once unpacked, and the unpacked copy lives in a tmpfs
/// the kernel caps at half of memory.
const BASE_MEMORY_MIB: u64 = 512;

/// Most virtual CPUs a guest gets.
const MAX_CPUS: usize = 4;

/// Exit code reported when the guest stopped without saying how the entrypoint
/// exited, the same "never ran to completion" code hakoniwa uses.
const NO_REPORT: i32 = 125;

/// A kernel a package ships, as a recipe declares it and the package metadata
/// records it.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct Kernel {
    /// The kernel image, relative to the package root, e.g. `boot/vmlinuz`.
    pub image: PathBuf,
    /// Extra kernel command-line parameters. pm's own come after them, so where the
    /// kernel takes the last of a repeated parameter, pm's wins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
}

impl Kernel {
    /// Check the declaration on its own, without looking at any file.
    ///
    /// The image has to be a plain package-relative path outside `deps/`, which
    /// belongs to other packages, and must not be the `metadata` member. The command
    /// line cannot contain `--`, after which the kernel hands everything to init,
    /// nor `init=` or `rdinit=`, which would replace pm's init, nor a NUL or a line
    /// break, and is capped at [`MAX_CMDLINE`] bytes.
    ///
    /// Run at build time on the recipe and again at run time on the metadata, which
    /// is as untrusted as the rest of the archive.
    ///
    /// # Errors
    ///
    /// Describes the first rule the declaration breaks.
    pub fn validate(&self) -> miette::Result<()> {
        if self.image.as_os_str().is_empty() {
            return Err(miette!("the kernel image path is empty"));
        }
        if let Some(component) = self
            .image
            .components()
            .find(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(miette!(
                help = "name the image relative to DESTDIR, e.g. kernel(image = \"boot/vmlinuz\")",
                "the kernel image {} must be a plain package-relative path, but it contains `{}`",
                self.image.display(),
                Path::new(component.as_os_str()).display()
            ));
        }
        if self.image.starts_with("deps") || self.image == Path::new("metadata") {
            return Err(miette!(
                "the kernel image cannot be {}: that path belongs to pm",
                self.image.display()
            ));
        }
        if let Some(cmdline) = &self.cmdline {
            if cmdline.len() > MAX_CMDLINE {
                return Err(miette!(
                    "the kernel command line is {} bytes; at most {MAX_CMDLINE} are allowed",
                    cmdline.len()
                ));
            }
            if cmdline.contains(['\0', '\n', '\r']) {
                return Err(miette!(
                    "the kernel command line contains a NUL or a line break"
                ));
            }
            if cmdline.split_whitespace().any(|word| word == "--") {
                return Err(miette!(
                    "the kernel command line cannot contain `--`: everything after it goes to \
                     pm's init"
                ));
            }
            if let Some(word) = cmdline.split_whitespace().find(|word| {
                let name = word.split_once('=').map_or(*word, |(name, _)| name);
                RESERVED_PARAMETERS.contains(&name)
            }) {
                return Err(miette!(
                    "the kernel command line cannot set `{word}`: pm decides which program \
                     runs as the guest's init"
                ));
            }
        }
        Ok(())
    }
}

/// Which kind of kernel image a file is, from its header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    /// An x86 `bzImage`, which is what `vmlinuz` usually is.
    BzImage,
    /// An uncompressed ELF `vmlinux` for the given `e_machine`.
    Elf {
        /// The ELF header's `e_machine`, e.g. 62 for x86-64.
        machine: u16,
    },
    /// An arm64 `Image`.
    Arm64,
    /// A RISC-V `Image`.
    RiscV,
}

impl ImageFormat {
    /// Read the header of `path` and say which kind of image it is.
    ///
    /// # Errors
    ///
    /// Fails if the file cannot be read or carries none of the four headers.
    pub fn of(path: &Path) -> miette::Result<Self> {
        let mut header = [0u8; 0x210];
        let mut file = File::open(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot open the kernel image {}", path.display()))?;
        let mut read = 0;
        while read < header.len() {
            match file.read(&mut header[read..]) {
                Ok(0) => break,
                Ok(count) => read += count,
                Err(error) => {
                    return Err(error).into_diagnostic().wrap_err_with(|| {
                        format!("cannot read the kernel image {}", path.display())
                    });
                }
            }
        }
        let header = &header[..read];
        let at =
            |offset: usize, magic: &[u8]| header.get(offset..offset + magic.len()) == Some(magic);
        if at(0, b"\x7fELF") {
            // `e_machine` is at the same offset in both ELF classes; read it in the
            // byte order `EI_DATA` names.
            let machine = header.get(18..20).ok_or_else(|| {
                miette!("{} is too short to be an ELF kernel image", path.display())
            })?;
            let machine = [machine[0], machine[1]];
            let machine = if header.get(5) == Some(&2) {
                u16::from_be_bytes(machine)
            } else {
                u16::from_le_bytes(machine)
            };
            Ok(Self::Elf { machine })
        } else if at(0x202, b"HdrS") {
            Ok(Self::BzImage)
        } else if at(0x38, b"ARM\x64") {
            Ok(Self::Arm64)
        } else if at(0x38, b"RSC\x05") {
            Ok(Self::RiscV)
        } else {
            Err(miette!(
                help = "stage a bzImage, a vmlinux, or an arm64 or RISC-V Image",
                "{} is not a Linux kernel image pm recognises",
                path.display()
            ))
        }
    }
}

impl ImageFormat {
    /// Whether QEMU's x86-64 `pc` machine can boot this image.
    #[must_use]
    pub fn boots_on_x86_64(self) -> bool {
        matches!(self, Self::BzImage | Self::Elf { machine: EM_X86_64 })
    }
}

/// What init runs, written to [`GUEST_CONFIG`] in the initramfs.
#[derive(Serialize, Deserialize, Debug)]
struct GuestConfig {
    entrypoint: PathBuf,
    cwd: PathBuf,
}

/// Everything [`boot`] needs to start one entrypoint under a package's kernel.
pub struct Boot<'a> {
    /// The kernel as the package metadata declared it.
    pub kernel: &'a Kernel,
    /// The extracted package. Must be canonical.
    pub package_root: &'a Path,
    /// The entrypoint to run, relative to `package_root`.
    pub entrypoint: &'a Path,
    /// Every ELF and script in the package whose host dependencies the guest needs,
    /// relative to `package_root`. Other programs the entrypoint starts need their
    /// libraries too, not only the entrypoint.
    pub programs: Vec<PathBuf>,
    /// The binary that runs as the guest's init. Must be a pm binary whose `main`
    /// starts with [`guest::is_guest_init`].
    pub init: &'a Path,
    /// The QEMU to start directly, skipping any launcher; `None` asks the launcher
    /// first and falls back to `qemu-system-x86_64` from `PATH`.
    pub qemu: Option<&'a Path>,
    /// What is asked to start the machine before pm starts QEMU itself.
    pub launcher: Option<&'a dyn Launcher>,
}

/// A machine ready to start: the initramfs is written, the status socket is
/// listening, and what the guest gets is decided. QEMU started directly and a
/// launcher's program both boot exactly this.
struct Prepared {
    /// Holds the initramfs and the sockets. Removed when this is dropped, which
    /// each starter does only once the machine is gone.
    scratch: Workspace,
    image: PathBuf,
    initramfs: PathBuf,
    memory_mib: u64,
    cpus: usize,
    cmdline: String,
    status: UnixListener,
    status_socket: PathBuf,
}

/// Boot the package's kernel in a virtual machine and run the entrypoint as its
/// only program.
///
/// The console is this process's stdin and stdout, so the entrypoint reads and
/// writes the terminal as it would in the jail. Returns how the entrypoint exited,
/// as init reported it.
///
/// # Errors
///
/// Fails on a non-x86-64 host, when the kernel image is missing, escapes the package
/// or is not an x86 image, when no QEMU is found, when the initramfs cannot be
/// written, when a launcher's answer is unusable, or when the machine cannot be
/// started. A guest that stops without init
/// reporting anything - a kernel panic, a kernel without a serial console - is not
/// an error: it comes back as exit code 125 with the reason.
pub fn boot(request: &Boot<'_>) -> miette::Result<ExitStatus> {
    if env::consts::ARCH != "x86_64" {
        return Err(miette!(
            help = "run it on the host kernel with --host-kernel",
            "booting a package's own kernel is only supported on x86-64 hosts; this one is {}",
            env::consts::ARCH
        ));
    }
    request.kernel.validate()?;
    let image = resolve_inside(request.package_root, &request.kernel.image)
        .wrap_err("the package's kernel image cannot be booted")?;
    let format = ImageFormat::of(&image)?;
    if !format.boots_on_x86_64() {
        return Err(miette!(
            help = "run it on the host kernel with --host-kernel",
            "the package's kernel is an {format:?} image, which an x86-64 host cannot boot"
        ));
    }
    if let (None, Some(launcher)) = (request.qemu, request.launcher) {
        let machine = Prepared::prepare(request, &image)?;
        match launch::ask(launcher, &machine, request)? {
            Some(plan) => return launch::run(plan, machine),
            None => debug!("no launcher answered; starting QEMU directly"),
        }
    }
    boot_qemu(request, &image, request.qemu)
}

impl Prepared {
    /// Write the initramfs, listen on the status socket, and size the machine.
    fn prepare(request: &Boot<'_>, image: &Path) -> miette::Result<Self> {
        let scratch = Workspace::new("vm")?;
        let initramfs = scratch.path().join("initramfs.cpio");
        let tree = Tree::assemble(request, image)?;
        let size = tree.write(&initramfs)?;
        let memory_mib = BASE_MEMORY_MIB + 3 * size.div_ceil(1024 * 1024);

        // The status port goes to a socket pm reads, not to a file: the guest can
        // write as much as it likes to the port, and only the last [`MAX_REPORT`]
        // bytes are kept. The hypervisor connects to it as a client when it starts.
        let status_socket = scratch.path().join("status.sock");
        let status = UnixListener::bind(&status_socket)
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot listen on {}", status_socket.display()))?;
        status.set_nonblocking(true).into_diagnostic()?;

        // pm's defaults, then the package's parameters, then the ones pm relies on.
        // The kernel keeps the last value of a repeated parameter, so a package can
        // turn the log level up but cannot change `panic`, nor which console is
        // `/dev/console`; `rdinit` it cannot set at all.
        let cmdline = format!(
            "quiet loglevel=1 {} console=ttyS0 panic=-1 rdinit=/init -- {}",
            request.kernel.cmdline.as_deref().unwrap_or(""),
            guest::INIT_ARG
        );
        let cpus = std::thread::available_parallelism().map_or(1, |n| n.get().min(MAX_CPUS));
        Ok(Self {
            scratch,
            image: image.to_path_buf(),
            initramfs,
            memory_mib,
            cpus,
            cmdline,
            status,
            status_socket,
        })
    }
}

/// Start QEMU directly, as the calling user, with the console on this process's
/// stdin and stdout.
fn boot_qemu(request: &Boot<'_>, image: &Path, qemu: Option<&Path>) -> miette::Result<ExitStatus> {
    let qemu = match qemu {
        Some(qemu) => qemu.to_path_buf(),
        None => find_on_path("qemu-system-x86_64").ok_or_else(|| {
            miette!(
                help = "install QEMU, or run it on the host kernel with --host-kernel",
                "this package ships its own kernel, and booting it needs qemu-system-x86_64, \
                 which is not on PATH"
            )
        })?,
    };
    // Declared before the child below, so it is removed only after QEMU is gone.
    let machine = Prepared::prepare(request, image)?;
    let mut status_device = OsString::from("socket,id=status,path=");
    status_device.push(qemu_option_value(&machine.status_socket));

    let mut command = Command::new(&qemu);
    command
        .args([
            "-nodefaults",
            "-no-user-config",
            "-no-reboot",
            "-display",
            "none",
        ])
        .args(["-machine", "pc"])
        .args(accelerator())
        .args(["-m", &format!("{}M", machine.memory_mib)])
        .args(["-smp", &machine.cpus.to_string()])
        .args(["-nic", "none"])
        .args(["-serial", "stdio"])
        .arg("-chardev")
        .arg(status_device)
        .args(["-serial", "chardev:status"])
        .arg("-kernel")
        .arg(&machine.image)
        .arg("-initrd")
        .arg(&machine.initramfs)
        .args(["-append", &machine.cmdline])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    debug!(?command, scratch = %machine.scratch.path().display(), "starting QEMU");
    info!(
        kernel = %request.kernel.image.display(),
        memory_mib = machine.memory_mib,
        "booting the package's own kernel in a virtual machine"
    );

    let program = qemu.display().to_string();
    let child = command
        .spawn()
        .into_diagnostic()
        .wrap_err_with(|| format!("cannot start {program}"))?;
    // Declared after `machine`, therefore dropped - and QEMU killed - before it.
    let child = HostChild::new(child, program.clone());
    let done = AtomicBool::new(false);
    let (exited, report) = thread::scope(|scope| {
        let reader = scope.spawn(|| read_report(&machine.status, &done));
        let exited = child.wait();
        done.store(true, Ordering::Release);
        (exited, reader.join().unwrap_or_default())
    });
    let exited = exited?;

    let status = parse_report(&report);
    if status.is_none() && !exited.success() {
        return Err(miette!(
            "{program} exited with {exited} before the guest reported anything"
        ));
    }
    Ok(status.unwrap_or_else(no_report))
}

/// The status of a guest that stopped without init saying how the entrypoint
/// exited.
fn no_report() -> ExitStatus {
    exit_status(
        NO_REPORT,
        None,
        "the guest stopped without reporting how the entrypoint exited; the kernel may \
         have panicked, or lacks a built-in serial console or initramfs support"
            .to_owned(),
    )
}

/// Accept the hypervisor's connection on `listener`, giving up once `done` is set,
/// which is after the machine has stopped: a hypervisor that never connected is not
/// going to.
fn accept(listener: &UnixListener, done: &AtomicBool) -> Option<UnixStream> {
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Some(stream),
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                if done.load(Ordering::Acquire) {
                    return None;
                }
                thread::sleep(POLL);
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => {
                warn!(%error, "cannot accept the hypervisor's connection");
                return None;
            }
        }
    }
}

/// Accept the hypervisor's connection on the status socket and read it until the
/// machine stops, keeping only the last [`MAX_REPORT`] bytes.
fn read_report(listener: &UnixListener, done: &AtomicBool) -> String {
    let Some(mut stream) = accept(listener, done) else {
        return String::new();
    };
    if stream.set_nonblocking(false).is_err() || stream.set_read_timeout(Some(POLL)).is_err() {
        return String::new();
    }
    let mut kept = Vec::with_capacity(MAX_REPORT);
    let mut buffer = [0u8; MAX_REPORT];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                kept.extend_from_slice(&buffer[..count]);
                if kept.len() > MAX_REPORT {
                    kept.drain(..kept.len() - MAX_REPORT);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                // Nothing arrived for a while. QEMU closes the socket when it exits,
                // so this only stops a read that would otherwise outlive it.
                if done.load(Ordering::Acquire) {
                    break;
                }
            }
            Err(error) => {
                warn!(%error, "cannot read the guest's status connection");
                break;
            }
        }
    }
    String::from_utf8_lossy(&kept).into_owned()
}

/// How often pm checks whether the machine has stopped.
const POLL: Duration = Duration::from_millis(50);

/// `path` as a value inside a QEMU `key=value,...` option, where a literal comma is
/// written twice.
fn qemu_option_value(path: &Path) -> OsString {
    let mut escaped = Vec::new();
    for &byte in path.as_os_str().as_bytes() {
        escaped.push(byte);
        if byte == b',' {
            escaped.push(b',');
        }
    }
    OsString::from_vec(escaped)
}

/// `-accel kvm` when `/dev/kvm` can be opened, TCG emulation otherwise.
fn accelerator() -> impl Iterator<Item = &'static str> {
    let args: &[&str] = if OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
    {
        &["-accel", "kvm", "-cpu", "host"]
    } else {
        warn!("/dev/kvm is not available; the guest is emulated and will be slow");
        &["-accel", "tcg"]
    };
    args.iter().copied()
}

/// Turn init's report into an exit status.
fn parse_report(report: &str) -> Option<ExitStatus> {
    let line = report
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty())?;
    let (kind, value) = line.split_once(' ')?;
    match kind {
        "exit" => {
            let code = value.parse().ok()?;
            Some(exit_status(
                code,
                Some(code),
                format!("entrypoint exited with code {code} in the guest"),
            ))
        }
        "signal" => {
            let signal: i32 = value.parse().ok()?;
            Some(exit_status(
                128 + signal,
                None,
                format!("entrypoint was killed by signal {signal} in the guest"),
            ))
        }
        "error" => Some(exit_status(
            NO_REPORT,
            None,
            format!("the guest's init failed: {value}"),
        )),
        _ => None,
    }
}

fn exit_status(code: i32, exit_code: Option<i32>, reason: String) -> ExitStatus {
    ExitStatus {
        code,
        reason,
        exit_code,
        rusage: None,
        proc_pid_smaps_rollup: None,
        proc_pid_status: None,
    }
}

/// `relative` joined to `root`, canonicalised and required to stay inside it.
fn resolve_inside(root: &Path, relative: &Path) -> miette::Result<PathBuf> {
    let joined = root.join(relative);
    let resolved = joined
        .canonicalize()
        .into_diagnostic()
        .wrap_err_with(|| format!("{} does not exist in the package", relative.display()))?;
    if !resolved.starts_with(root) {
        return Err(miette!(
            "{} resolves to {}, outside the package",
            relative.display(),
            resolved.display()
        ));
    }
    if !resolved.is_file() {
        return Err(miette!("{} is not a regular file", relative.display()));
    }
    Ok(resolved)
}

/// `program` as the first regular file of that name in a `PATH` directory, the way a
/// shell finds it.
pub fn find_on_path(program: &str) -> Option<PathBuf> {
    env::split_paths(&env::var_os("PATH")?)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

/// One member of the initramfs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Member {
    Directory,
    /// A host file, copied with these permission bits.
    File(PathBuf, u32),
    Bytes(Vec<u8>, u32),
    Symlink(PathBuf),
    CharacterDevice(u32, u32),
}

/// The guest's root filesystem, keyed by path relative to `/`.
///
/// A sorted map, because the kernel needs every directory before what is in it,
/// and [`Path`] orders a parent before its children.
#[derive(Default)]
struct Tree(BTreeMap<PathBuf, Member>);

impl Tree {
    /// Lay out everything the guest gets; see the module documentation.
    fn assemble(request: &Boot<'_>, image: &Path) -> miette::Result<Self> {
        let mut tree = Self::default();
        for directory in ["dev", "proc", "sys", "tmp"] {
            tree.insert(PathBuf::from(directory), Member::Directory);
        }
        for (name, major, minor) in [
            ("console", 5, 1),
            ("null", 1, 3),
            ("zero", 1, 5),
            ("random", 1, 8),
            ("urandom", 1, 9),
            ("tty", 5, 0),
            ("ttyS0", 4, 64),
            ("ttyS1", 4, 65),
        ] {
            tree.insert(
                Path::new("dev").join(name),
                Member::CharacterDevice(major, minor),
            );
        }

        let init = request
            .init
            .canonicalize()
            .into_diagnostic()
            .wrap_err_with(|| {
                format!("cannot find pm's own binary at {}", request.init.display())
            })?;
        tree.insert(PathBuf::from("init"), Member::File(init.clone(), 0o755));

        let entrypoint = Path::new(GUEST_PACKAGE_ROOT).join(request.entrypoint);
        let config = serde_json::to_vec(&GuestConfig {
            entrypoint,
            cwd: PathBuf::from(GUEST_PACKAGE_ROOT),
        })
        .into_diagnostic()?;
        tree.insert(
            relative(Path::new(GUEST_CONFIG)),
            Member::Bytes(config, 0o644),
        );

        tree.add_package(request.package_root, image)?;

        let roots = std::iter::once(init.clone())
            .chain(std::iter::once(
                request.package_root.join(request.entrypoint),
            ))
            .chain(
                request
                    .programs
                    .iter()
                    .map(|program| request.package_root.join(program)),
            );
        for file in closure::host_files(roots, request.package_root, &init) {
            // init itself is already in the tree, at `/init`.
            if file == init {
                continue;
            }
            // `host_files` returns absolute, normalised paths, so this only drops
            // the leading `/`.
            let guest = relative(&closure::normalize(&file));
            if guest.as_os_str().is_empty() {
                continue;
            }
            tree.insert(guest, Member::File(file, 0o755));
        }
        Ok(tree)
    }

    /// Add the extracted package under [`GUEST_PACKAGE_ROOT`], leaving out `image`.
    fn add_package(&mut self, package_root: &Path, image: &Path) -> miette::Result<()> {
        let base = relative(Path::new(GUEST_PACKAGE_ROOT));
        for entry in WalkDir::new(package_root).follow_links(false) {
            let entry = entry
                .into_diagnostic()
                .wrap_err_with(|| format!("cannot walk {}", package_root.display()))?;
            let path = entry.path();
            if path == image {
                continue;
            }
            let Ok(inside) = path.strip_prefix(package_root) else {
                continue;
            };
            // `join("")` would add a trailing slash to the package root itself.
            let guest = if inside.as_os_str().is_empty() {
                base.clone()
            } else {
                base.join(inside)
            };
            let file_type = entry.file_type();
            let member = if file_type.is_dir() {
                Member::Directory
            } else if file_type.is_symlink() {
                let target = std::fs::read_link(path)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("cannot read the link {}", path.display()))?;
                Member::Symlink(target)
            } else if file_type.is_file() {
                let mode = entry
                    .metadata()
                    .into_diagnostic()
                    .wrap_err_with(|| format!("cannot stat {}", path.display()))?
                    .permissions()
                    .mode();
                Member::File(path.to_path_buf(), mode & 0o7777)
            } else {
                debug!(path = %path.display(), "leaving a special file out of the guest");
                continue;
            };
            self.insert(guest, member);
        }
        Ok(())
    }

    /// Add `member` at `path`, and every missing directory above it.
    fn insert(&mut self, path: PathBuf, member: Member) {
        for ancestor in path.ancestors().skip(1) {
            if ancestor.as_os_str().is_empty() {
                break;
            }
            self.0
                .entry(ancestor.to_path_buf())
                .or_insert(Member::Directory);
        }
        self.0.insert(path, member);
    }

    /// Write the tree as a `newc` archive at `path` and return its size in bytes.
    fn write(&self, path: &Path) -> miette::Result<u64> {
        let file = File::create(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot create {}", path.display()))?;
        let mut archive = Newc::new(BufWriter::new(file));
        archive.directory(Path::new("."), 0o755)?;
        for (name, member) in &self.0 {
            match member {
                Member::Directory => {
                    let permissions = if name == Path::new("tmp") {
                        0o1777
                    } else {
                        0o755
                    };
                    archive.directory(name, permissions)?;
                }
                Member::File(source, permissions) => archive.file(name, *permissions, source)?,
                Member::Bytes(data, permissions) => archive.bytes(name, *permissions, data)?,
                Member::Symlink(target) => archive.symlink(name, target)?,
                Member::CharacterDevice(major, minor) => {
                    archive.character_device(name, 0o666, *major, *minor)?;
                }
            }
        }
        let size = archive
            .finish()?
            .into_inner()
            .map_err(|error| miette!("cannot finish writing the initramfs: {error}"))?
            .metadata()
            .into_diagnostic()?
            .len();
        debug!(members = self.0.len(), bytes = size, "wrote the initramfs");
        Ok(size)
    }
}

/// `path` without its leading `/`.
fn relative(path: &Path) -> PathBuf {
    path.components()
        .filter(|component| matches!(component, Component::Normal(_)))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn kernel(image: &str, cmdline: Option<&str>) -> Kernel {
        Kernel {
            image: PathBuf::from(image),
            cmdline: cmdline.map(str::to_owned),
        }
    }

    #[test]
    fn a_plain_relative_image_is_valid() {
        kernel("boot/vmlinuz", Some("quiet mitigations=off"))
            .validate()
            .unwrap();
    }

    #[test]
    fn an_image_outside_the_package_or_in_pms_paths_is_refused() {
        for image in [
            "",
            "/boot/vmlinuz",
            "../vmlinuz",
            "boot/../vmlinuz",
            "deps/x",
            "metadata",
        ] {
            assert!(kernel(image, None).validate().is_err(), "{image}");
        }
    }

    #[test]
    fn a_cmdline_cannot_choose_init() {
        for cmdline in ["rdinit=/pkg/bin/sh", "quiet init=/bin/sh", "rdinit"] {
            assert!(
                kernel("vmlinuz", Some(cmdline)).validate().is_err(),
                "{cmdline}"
            );
        }
        kernel("vmlinuz", Some("initcall_debug foo.rdinit=1"))
            .validate()
            .unwrap();
    }

    #[test]
    fn a_comma_in_a_qemu_option_value_is_doubled() {
        assert_eq!(
            qemu_option_value(Path::new("/tmp/a,b/status.sock")),
            OsString::from("/tmp/a,,b/status.sock")
        );
    }

    #[test]
    fn the_status_reader_keeps_only_the_end_of_a_flood() {
        use std::{io::Write, os::unix::net::UnixStream};

        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("status.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let reader = {
            let done = Arc::clone(&done);
            thread::spawn(move || read_report(&listener, &done))
        };
        let mut guest = UnixStream::connect(&socket).unwrap();
        for _ in 0..1024 {
            guest.write_all(&[b'x'; 1024]).unwrap();
        }
        guest.write_all(b"\r\nexit 4\r\n").unwrap();
        drop(guest);
        let report = reader.join().unwrap();
        assert_eq!(report.len(), MAX_REPORT);
        assert_eq!(parse_report(&report).unwrap().exit_code, Some(4));
    }

    #[test]
    fn the_status_reader_stops_when_qemu_never_connects() {
        let dir = tempfile::tempdir().unwrap();
        let listener = UnixListener::bind(dir.path().join("status.sock")).unwrap();
        listener.set_nonblocking(true).unwrap();
        let done = AtomicBool::new(true);
        assert_eq!(read_report(&listener, &done), "");
    }

    #[test]
    fn a_cmdline_that_reaches_init_is_refused() {
        assert!(kernel("vmlinuz", Some("quiet -- sh")).validate().is_err());
        assert!(kernel("vmlinuz", Some("a\nb")).validate().is_err());
        assert!(
            kernel("vmlinuz", Some(&"x".repeat(MAX_CMDLINE + 1)))
                .validate()
                .is_err()
        );
        kernel("vmlinuz", Some("foo--bar")).validate().unwrap();
    }

    #[test]
    fn image_formats_are_read_from_their_headers() {
        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, offset: usize, magic: &[u8]| {
            let mut bytes = vec![0u8; 0x300];
            bytes[offset..offset + magic.len()].copy_from_slice(magic);
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            path
        };
        assert_eq!(
            ImageFormat::of(&write("bz", 0x202, b"HdrS")).unwrap(),
            ImageFormat::BzImage
        );
        // ELFCLASS64, ELFDATA2LSB, then e_machine at 18.
        let elf = |name: &str, machine: u16| {
            let mut header = b"\x7fELF\x02\x01".to_vec();
            header.resize(18, 0);
            header.extend_from_slice(&machine.to_le_bytes());
            write(name, 0, &header)
        };
        let x86 = ImageFormat::of(&elf("x86", EM_X86_64)).unwrap();
        assert_eq!(x86, ImageFormat::Elf { machine: EM_X86_64 });
        assert!(x86.boots_on_x86_64());
        // EM_AARCH64: an arm64 vmlinux is an ELF too, and must not be booted.
        let arm = ImageFormat::of(&elf("aarch64", 183)).unwrap();
        assert_eq!(arm, ImageFormat::Elf { machine: 183 });
        assert!(!arm.boots_on_x86_64());
        assert_eq!(
            ImageFormat::of(&write("arm", 0x38, b"ARM\x64")).unwrap(),
            ImageFormat::Arm64
        );
        assert_eq!(
            ImageFormat::of(&write("rv", 0x38, b"RSC\x05")).unwrap(),
            ImageFormat::RiscV
        );
        assert!(ImageFormat::of(&write("junk", 0, b"junk")).is_err());
        let short = dir.path().join("short");
        std::fs::write(&short, b"\x7fEL").unwrap();
        assert!(ImageFormat::of(&short).is_err());
    }

    #[test]
    fn reports_become_exit_statuses() {
        let exit = parse_report("exit 3\r\n").unwrap();
        assert_eq!((exit.code, exit.exit_code), (3, Some(3)));
        let signal = parse_report("signal 9\n").unwrap();
        assert_eq!((signal.code, signal.exit_code), (137, None));
        assert_eq!(
            parse_report("error cannot start /pkg/x").unwrap().code,
            NO_REPORT
        );
        assert!(parse_report("").is_none());
        assert!(parse_report("garbage").is_none());
    }

    #[test]
    fn the_tree_has_every_parent_before_its_children() {
        let mut tree = Tree::default();
        tree.insert(
            PathBuf::from("usr/lib/x/libc.so.6"),
            Member::Bytes(vec![], 0o755),
        );
        tree.insert(PathBuf::from("dev/console"), Member::CharacterDevice(5, 1));
        let paths: Vec<_> = tree.0.keys().cloned().collect();
        assert_eq!(
            paths,
            [
                "dev",
                "dev/console",
                "usr",
                "usr/lib",
                "usr/lib/x",
                "usr/lib/x/libc.so.6"
            ]
            .map(PathBuf::from)
        );
    }
}

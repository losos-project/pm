//! `pm system ...`: asks `pmd --system` to administer the machine.
//!
//! Each call carries D-Bus's allow-interactive-authorization flag, so polkit
//! may ask the person to authenticate: through their desktop's agent when one
//! is registered for their session, otherwise through `pkttyagent` on this
//! terminal, which [`TtyAgent`] starts for the length of the call, as
//! systemctl does.
//!
//! `pm system run` gives the root command a pseudo-terminal of its own and
//! relays this terminal to it, rather than handing over this one: a terminal
//! is the controlling terminal of one session, and giving the caller's to
//! root would take it from the caller's shell.

use std::{
    collections::HashMap,
    env,
    io::{self, IsTerminal, Read, Write},
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use miette::{IntoDiagnostic, WrapErr, miette};
use nix::{
    fcntl::{FcntlArg, FdFlag, OFlag, fcntl},
    libc,
    poll::{PollFd, PollFlags, PollTimeout, poll},
    pty::{Winsize, openpty},
    sys::{
        signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction},
        termios::{SetArg, Termios, cfmakeraw, tcgetattr, tcsetattr},
    },
    unistd::{pipe2, ttyname},
};
use zbus::{
    MatchRule,
    blocking::{Connection, MessageIterator, Proxy, fdo::DBusProxy},
    message::Type,
    proxy::MethodFlags,
};

use super::{BUS_NAME, INTERFACE, OBJECT_PATH, STARTED_SIGNAL, Verb, exit_status, unit_name};

/// How long the relay threads wait on a descriptor before looking at whether
/// they should stop.
const POLL: u16 = 100;

/// Set by the `SIGWINCH` handler; the relay copies the new size across.
static RESIZED: AtomicBool = AtomicBool::new(false);

/// `pm system start|stop|restart|reload UNIT`.
///
/// # Errors
///
/// The unit name is not one, the daemon cannot be reached, polkit said no,
/// or the job failed.
pub fn manage(verb: Verb, unit: &str) -> miette::Result<()> {
    let unit = unit_name(unit).map_err(|error| miette!("{error}"))?;
    let connection = connect()?;
    let _agent = TtyAgent::start();
    call::<()>(&connection, "Manage", &(verb.as_str(), unit.as_str()))
}

/// `pm system update [--reboot]`.
///
/// # Errors
///
/// The daemon cannot be reached, polkit said no, or the update failed.
pub fn update(reboot: bool) -> miette::Result<()> {
    let connection = connect()?;
    let _agent = TtyAgent::start();
    call::<()>(&connection, "Update", &(reboot,))
}

/// `pm system run [COMMAND...]`: runs `argv`, or root's shell, as root, and
/// returns the exit status to leave with.
///
/// # Errors
///
/// No pseudo-terminal, the daemon cannot be reached, polkit said no, or the
/// command did not start.
pub fn run(argv: Vec<String>) -> miette::Result<i32> {
    let stdin = io::stdin();
    let size = window_size(stdin.as_fd());
    let pty = openpty(size.as_ref(), None)
        .into_diagnostic()
        .wrap_err("cannot open a pseudo-terminal")?;
    // The slave stays open here for the whole run, so the master never reads
    // as hung up before the command opens it or after it closes it: the call
    // returning is what ends the relay.
    let tty = ttyname(&pty.slave)
        .into_diagnostic()
        .wrap_err("cannot name the pseudo-terminal")?;
    let cwd = env::current_dir()
        .map(|dir| dir.display().to_string())
        .unwrap_or_default();
    let env: HashMap<String, String> = env::vars().collect();

    let connection = connect()?;
    let started = Arc::new(AtomicBool::new(false));
    watch_started(&connection, Arc::clone(&started))?;
    let agent = Mutex::new(TtyAgent::start());
    let saved = Mutex::new(None);
    let done = AtomicBool::new(false);
    let _ = on_resize();

    let reply = thread::scope(|scope| {
        scope.spawn(|| {
            relay_in(&pty.master, &started, &done, || {
                // The terminal is the command's from here on: the agent has
                // nothing left to ask, and keystrokes go through unread.
                drop(agent.lock().unwrap_or_else(PoisonError::into_inner).take());
                *saved.lock().unwrap_or_else(PoisonError::into_inner) =
                    make_raw(io::stdin().as_fd());
            });
        });
        scope.spawn(|| relay_out(&pty.master, &done));
        let reply = call::<(i32, i32)>(
            &connection,
            "Run",
            &(argv, cwd.as_str(), tty.display().to_string(), env),
        );
        done.store(true, Ordering::SeqCst);
        reply
    });
    if let Some(termios) = saved.into_inner().unwrap_or_else(PoisonError::into_inner) {
        let _ = tcsetattr(io::stdin().as_fd(), SetArg::TCSAFLUSH, &termios);
    }
    drop(pty);
    let (code, status) = reply?;
    Ok(exit_status(code, status))
}

fn connect() -> miette::Result<Connection> {
    Connection::system()
        .into_diagnostic()
        .wrap_err("cannot reach the system bus")
}

/// Calls `method` on the daemon, letting polkit ask for authentication.
fn call<R>(
    connection: &Connection,
    method: &str,
    body: &(impl serde::Serialize + zbus::zvariant::DynamicType),
) -> miette::Result<R>
where
    R: for<'d> zbus::zvariant::DynamicDeserialize<'d>,
{
    let proxy = Proxy::new(connection, BUS_NAME, OBJECT_PATH, INTERFACE)
        .into_diagnostic()
        .wrap_err("cannot reach pm's system service")?;
    match proxy.call_with_flags::<_, _, R>(method, MethodFlags::AllowInteractiveAuth.into(), body) {
        Ok(Some(reply)) => Ok(reply),
        Ok(None) => Err(miette!("{BUS_NAME} sent no reply")),
        Err(zbus::Error::MethodError(name, message, _)) => {
            let message = message.unwrap_or_else(|| name.to_string());
            match name.as_str() {
                "org.freedesktop.DBus.Error.AccessDenied"
                | "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired" => Err(miette!(
                    help = "an administrator has to authenticate; polkit asks through the \
                            desktop, or in this terminal when nothing else can",
                    "{message}"
                )),
                "org.freedesktop.DBus.Error.ServiceUnknown" => Err(miette!(
                    help = "pm's system service is not installed on this machine",
                    "{message}"
                )),
                _ => Err(miette!("{message}")),
            }
        }
        Err(error) => Err(error)
            .into_diagnostic()
            .wrap_err("pm's system service failed"),
    }
}

/// Sets `started` once the daemon sends this connection `Started`, from a
/// thread of its own that outlives nothing: it ends with the process.
fn watch_started(connection: &Connection, started: Arc<AtomicBool>) -> miette::Result<()> {
    let rule = MatchRule::builder()
        .msg_type(Type::Signal)
        .interface(INTERFACE)
        .and_then(|rule| rule.member(STARTED_SIGNAL))
        .and_then(|rule| rule.path(OBJECT_PATH))
        .map(zbus::match_rule::Builder::build)
        .into_diagnostic()?;
    // Made before the call, so the signal cannot come before anyone listens.
    let messages = MessageIterator::for_match_rule(rule, connection, None).into_diagnostic()?;
    let bus = DBusProxy::new(connection).into_diagnostic()?;
    thread::spawn(move || {
        for message in messages.flatten() {
            // Only the daemon may say when the terminal is the command's.
            let from_daemon = message.header().sender().is_some_and(|sender| {
                bus.get_name_owner(BUS_NAME.try_into().expect("a valid bus name"))
                    .is_ok_and(|owner| owner.as_str() == sender.as_str())
            });
            if from_daemon {
                started.store(true, Ordering::SeqCst);
                return;
            }
        }
    });
    Ok(())
}

/// Copies this terminal's input to the command's, once it has started.
fn relay_in(master: &OwnedFd, started: &AtomicBool, done: &AtomicBool, on_start: impl FnOnce()) {
    while !started.load(Ordering::SeqCst) {
        if done.load(Ordering::SeqCst) {
            return;
        }
        thread::sleep(Duration::from_millis(POLL.into()));
    }
    on_start();
    let mut stdin = io::stdin().lock();
    let mut buffer = [0; 4096];
    while !done.load(Ordering::SeqCst) {
        if !readable(stdin.as_fd()) {
            continue;
        }
        match stdin.read(&mut buffer) {
            // Input ended (a pipe, not a terminal): pass the end on as the
            // terminal's end-of-file character, once.
            Ok(0) => {
                let _ = nix::unistd::write(master, &[4]);
                return;
            }
            Ok(n) => {
                if nix::unistd::write(master, &buffer[..n]).is_err() {
                    return;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

/// Copies the command's output to this terminal until the call returns, then
/// what is left.
fn relay_out(master: &OwnedFd, done: &AtomicBool) {
    let mut stdout = io::stdout().lock();
    let mut buffer = [0; 4096];
    loop {
        let finished = done.load(Ordering::SeqCst);
        if RESIZED.swap(false, Ordering::SeqCst)
            && let Some(size) = window_size(io::stdin().as_fd())
        {
            set_window_size(master.as_fd(), &size);
        }
        let ready = poll(
            &mut [PollFd::new(master.as_fd(), PollFlags::POLLIN)],
            if finished {
                PollTimeout::ZERO
            } else {
                PollTimeout::from(POLL)
            },
        )
        .unwrap_or(0);
        if ready == 0 {
            if finished {
                return;
            }
            continue;
        }
        match nix::unistd::read(master, &mut buffer) {
            Ok(n) if n > 0 => {
                let _ = stdout.write_all(&buffer[..n]).and_then(|()| stdout.flush());
            }
            Ok(_) | Err(nix::errno::Errno::EIO) => {
                if finished {
                    return;
                }
                thread::sleep(Duration::from_millis(POLL.into()));
            }
            Err(nix::errno::Errno::EINTR) => {}
            Err(_) => return,
        }
    }
}

fn readable(fd: BorrowedFd<'_>) -> bool {
    poll(
        &mut [PollFd::new(fd, PollFlags::POLLIN)],
        PollTimeout::from(POLL),
    )
    .is_ok_and(|n| n > 0)
}

/// Puts the terminal on `fd` into raw mode, so keys reach the command as
/// typed, and returns its old settings; `None` when it is no terminal.
fn make_raw(fd: BorrowedFd<'_>) -> Option<Termios> {
    let saved = tcgetattr(fd).ok()?;
    let mut raw = saved.clone();
    cfmakeraw(&mut raw);
    tcsetattr(fd, SetArg::TCSANOW, &raw).ok()?;
    Some(saved)
}

fn window_size(fd: BorrowedFd<'_>) -> Option<Winsize> {
    let mut size = Winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ writes one `winsize` through the pointer, which
    // points at one.
    let read = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCGWINSZ, &raw mut size) };
    (read == 0).then_some(size)
}

fn set_window_size(fd: BorrowedFd<'_>, size: &Winsize) {
    // SAFETY: TIOCSWINSZ reads one `winsize` through the pointer, which
    // points at one.
    unsafe { libc::ioctl(fd.as_raw_fd(), libc::TIOCSWINSZ, &raw const *size) };
}

/// Notes window changes in [`RESIZED`].
fn on_resize() -> nix::Result<()> {
    extern "C" fn resized(_: libc::c_int) {
        RESIZED.store(true, Ordering::SeqCst);
    }
    let action = SigAction::new(
        SigHandler::Handler(resized),
        SaFlags::SA_RESTART,
        SigSet::empty(),
    );
    // SAFETY: the handler only stores to an atomic, which is
    // async-signal-safe.
    unsafe { sigaction(Signal::SIGWINCH, &action) }.map(drop)
}

/// polkit's text agent, `pkttyagent`, registered for this terminal's session
/// as a fallback: a desktop's own agent still answers first.
struct TtyAgent(Child);

impl TtyAgent {
    /// Starts it when input is a terminal and it is installed, and waits
    /// until it has registered, so polkit can find it when the call needs it.
    fn start() -> Option<Self> {
        if !io::stdin().is_terminal() {
            return None;
        }
        let (ready, notify) = pipe2(OFlag::O_CLOEXEC).ok()?;
        // The agent closes its end of the pipe once it is registered. Only
        // that end crosses into it.
        fcntl(&notify, FcntlArg::F_SETFD(FdFlag::empty())).ok()?;
        let child = Command::new("pkttyagent")
            .args(["--notify-fd", &notify.as_raw_fd().to_string(), "--fallback"])
            .stdout(Stdio::null())
            .spawn()
            .ok()?;
        drop(notify);
        let mut ready = std::fs::File::from(ready);
        let _ = ready.read(&mut [0]);
        Some(Self(child))
    }
}

impl Drop for TtyAgent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

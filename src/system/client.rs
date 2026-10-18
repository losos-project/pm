//! `pm system ...`: asks `pmd --system` to administer the machine.
//!
//! Each call carries D-Bus's allow-interactive-authorization flag, so polkit
//! may ask the person to authenticate: through their desktop's agent when one
//! is registered for their session, otherwise through `pkttyagent` on this
//! terminal, which [`TtyAgent`] starts for the length of the call, as
//! systemctl does.

use std::{
    io::{self, IsTerminal, Read},
    os::fd::AsRawFd,
    process::{Child, Command, Stdio},
};

use miette::{IntoDiagnostic, WrapErr, miette};
use nix::{
    fcntl::{FcntlArg, FdFlag, OFlag, fcntl},
    unistd::pipe2,
};
use zbus::{
    blocking::{Connection, Proxy},
    proxy::MethodFlags,
};

use super::{BUS_NAME, INTERFACE, OBJECT_PATH, Verb, unit_name};

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

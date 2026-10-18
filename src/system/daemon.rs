//! `pmd --system`: the `org.pm1.System` service, running as the `pm` user.
//!
//! Every method asks polkit about its caller first, with the caller's
//! permission to be asked to authenticate when the call carries it, and only
//! then acts. It acts through systemd, as `pm`: the distribution's polkit
//! rules are what let `pm` manage units, so the daemon itself has nothing
//! to protect beyond its own correctness.
//!
//! polkit answers questions about a subject only to that subject's own user,
//! to root, and to the users an action names as its owner
//! (`org.freedesktop.policykit.owner`). `data/polkit-1/actions/` names `pm`
//! as the owner of every action here, which is what lets an unprivileged
//! daemon ask about other people's processes.
//!
//! The service is bus-activated and leaves once it has had nothing to do for
//! [`IDLE`], so it costs nothing on a machine nobody administers.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use futures_lite::StreamExt;
use miette::{IntoDiagnostic, WrapErr};
use tracing::{info, warn};
use zbus::{
    Connection, fdo, interface,
    message::{Flags, Header},
    names::{BusName, UniqueName},
    zvariant::{OwnedObjectPath, Value},
};

use super::{
    ACTION_MANAGE_UNITS, ACTION_UPDATE, BUS_NAME, OBJECT_PATH, Verb,
    proxies::{AuthorityProxy, ManagerProxy},
    unit_name,
};

/// How long the daemon stays with nothing to do before it leaves the bus.
/// The next call starts it again.
const IDLE: Duration = Duration::from_secs(60);

/// How often the main thread looks at whether the daemon is idle.
const IDLE_CHECK: Duration = Duration::from_secs(5);

/// The unit `Update` starts: systemd-sysupdate's own, which downloads and
/// installs the newest version into the slot not booted.
const SYSUPDATE_UNIT: &str = "systemd-sysupdate.service";

/// The unit that reboots into what [`SYSUPDATE_UNIT`] installed, and does
/// nothing when it installed nothing.
const SYSUPDATE_REBOOT_UNIT: &str = "systemd-sysupdate-reboot.service";

/// Serves `org.pm1.System` on the system bus until it has been idle for
/// [`IDLE`].
///
/// # Errors
///
/// The system bus cannot be reached, or the name is taken.
pub fn serve() -> miette::Result<()> {
    let activity = Arc::new(Activity::new());
    let connection = zbus::blocking::connection::Builder::system()
        .and_then(|builder| builder.name(BUS_NAME))
        .and_then(|builder| {
            builder.serve_at(
                OBJECT_PATH,
                System {
                    activity: Arc::clone(&activity),
                },
            )
        })
        .and_then(zbus::blocking::connection::Builder::build)
        .into_diagnostic()
        .wrap_err_with(|| format!("cannot serve {BUS_NAME} on the system bus"))?;
    info!("serving {BUS_NAME}");

    // zbus answers calls on its own executor thread; this one only decides
    // when to leave. The name goes first, so the bus starts a new daemon for
    // any call that comes after, and the calls already here are finished
    // before the process exits.
    while activity.idle_for() < IDLE {
        thread::sleep(IDLE_CHECK);
    }
    connection
        .release_name(BUS_NAME)
        .into_diagnostic()
        .wrap_err("cannot release the bus name")?;
    while activity.busy() {
        thread::sleep(IDLE_CHECK);
    }
    info!("idle, leaving");
    Ok(())
}

/// How many calls are in flight, and when the last one ended.
struct Activity {
    calls: AtomicUsize,
    last: Mutex<Instant>,
}

impl Activity {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            last: Mutex::new(Instant::now()),
        }
    }

    /// Counts a call until the returned guard drops.
    fn enter(&self) -> Busy<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Busy(self)
    }

    fn busy(&self) -> bool {
        self.calls.load(Ordering::SeqCst) > 0
    }

    /// Zero while a call is in flight, else the time since the last one ended.
    fn idle_for(&self) -> Duration {
        if self.busy() {
            return Duration::ZERO;
        }
        self.last
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .elapsed()
    }
}

/// One call in flight; see [`Activity::enter`].
struct Busy<'a>(&'a Activity);

impl Drop for Busy<'_> {
    fn drop(&mut self) {
        *self.0.last.lock().unwrap_or_else(PoisonError::into_inner) = Instant::now();
        self.0.calls.fetch_sub(1, Ordering::SeqCst);
    }
}

/// The `org.pm1.System` object.
struct System {
    activity: Arc<Activity>,
}

#[interface(name = "org.pm1.System")]
impl System {
    /// Starts, stops, restarts or reloads `unit`, and returns once systemd's
    /// job for it has finished.
    async fn manage(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
        verb: String,
        unit: String,
    ) -> fdo::Result<()> {
        let _busy = self.activity.enter();
        let verb = Verb::from_name(&verb)
            .ok_or_else(|| fdo::Error::InvalidArgs(format!("{verb:?} is not a verb")))?;
        let unit = unit_name(&unit).map_err(fdo::Error::InvalidArgs)?;
        let caller = Caller::of(connection, &header).await?;
        caller
            .authorize(
                connection,
                ACTION_MANAGE_UNITS,
                HashMap::from([("verb", verb.as_str()), ("unit", unit.as_str())]),
            )
            .await?;
        info!(
            uid = caller.uid,
            verb = verb.as_str(),
            unit,
            "managing a unit"
        );
        run_job(connection, verb, &unit).await
    }

    /// Installs the newest version of the system, and reboots into it when
    /// `reboot` is set and there was one.
    async fn update(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
        reboot: bool,
    ) -> fdo::Result<()> {
        let _busy = self.activity.enter();
        let caller = Caller::of(connection, &header).await?;
        caller
            .authorize(connection, ACTION_UPDATE, HashMap::new())
            .await?;
        info!(uid = caller.uid, reboot, "updating the system");
        run_job(connection, Verb::Start, SYSUPDATE_UNIT).await?;
        if reboot {
            run_job(connection, Verb::Start, SYSUPDATE_REBOOT_UNIT).await?;
        }
        Ok(())
    }
}

/// Who sent a call: their unique bus name, which polkit identifies them by,
/// and their uid, which the logs use.
struct Caller {
    name: UniqueName<'static>,
    uid: u32,
    /// Whether the call allows polkit to ask them to authenticate.
    interactive: bool,
}

impl Caller {
    async fn of(connection: &Connection, header: &Header<'_>) -> fdo::Result<Self> {
        let name = header
            .sender()
            .ok_or_else(|| fdo::Error::AccessDenied("the call has no sender".to_owned()))?
            .to_owned();
        let uid = fdo::DBusProxy::new(connection)
            .await?
            .get_connection_unix_user(BusName::Unique(name.clone()))
            .await?;
        Ok(Self {
            name,
            uid,
            interactive: header
                .primary()
                .flags()
                .contains(Flags::AllowInteractiveAuth),
        })
    }

    /// Asks polkit whether this caller may do `action`, letting it ask them to
    /// authenticate when their call allowed that. `details` fill in the
    /// `$(...)` of the action's message.
    async fn authorize(
        &self,
        connection: &Connection,
        action: &str,
        details: HashMap<&str, &str>,
    ) -> fdo::Result<()> {
        /// `AllowUserInteraction`, polkit's only flag.
        const ALLOW_USER_INTERACTION: u32 = 1;
        let subject = (
            "system-bus-name",
            HashMap::from([("name", Value::from(self.name.as_str()))]),
        );
        let flags = if self.interactive {
            ALLOW_USER_INTERACTION
        } else {
            0
        };
        let (authorized, challenge, _) = AuthorityProxy::new(connection)
            .await
            .map_err(failed)?
            .check_authorization(&subject, action, &details, flags, "")
            .await
            .map_err(failed)?;
        if authorized {
            Ok(())
        } else if challenge {
            Err(fdo::Error::InteractiveAuthorizationRequired(format!(
                "{action} needs an administrator to authenticate"
            )))
        } else {
            warn!(uid = self.uid, action, "refused");
            Err(fdo::Error::AccessDenied(format!("not allowed to {action}")))
        }
    }
}

/// Asks systemd to `verb` `unit` and waits for the job to finish.
async fn run_job(connection: &Connection, verb: Verb, unit: &str) -> fdo::Result<()> {
    let manager = ManagerProxy::new(connection).await.map_err(failed)?;
    subscribe(&manager).await;
    // Listening starts before the job does, so its end cannot be missed.
    let mut removed = manager.receive_job_removed().await.map_err(failed)?;
    let job = match verb {
        Verb::Start => manager.start_unit(unit, "replace").await,
        Verb::Stop => manager.stop_unit(unit, "replace").await,
        Verb::Restart => manager.restart_unit(unit, "replace").await,
        Verb::Reload => manager.reload_unit(unit, "replace").await,
    }
    .map_err(failed)?;
    match job_result(&mut removed, &job).await?.as_str() {
        "done" => Ok(()),
        result => Err(fdo::Error::Failed(format!(
            "{} {unit}: {result}; journalctl -u {unit} says why",
            verb.as_str()
        ))),
    }
}

/// systemd sends job and unit signals only to clients that asked. Asking
/// twice is harmless, and a failure only means waiting on signals that may
/// not come, which the caller then sees as a call that does not return; so
/// it is logged, not returned.
async fn subscribe(manager: &ManagerProxy<'_>) {
    if let Err(error) = manager.subscribe().await {
        warn!(%error, "cannot subscribe to systemd's signals");
    }
}

/// How `job` ended, from the `JobRemoved` signals in `removed`.
async fn job_result(
    removed: &mut super::proxies::JobRemovedStream,
    job: &OwnedObjectPath,
) -> fdo::Result<String> {
    while let Some(signal) = removed.next().await {
        let args = signal.args().map_err(failed)?;
        if args.job() == &job.as_ref() {
            return Ok((*args.result()).to_owned());
        }
    }
    Err(fdo::Error::Failed(
        "lost systemd before the job finished".to_owned(),
    ))
}

fn failed(error: zbus::Error) -> fdo::Error {
    match error {
        zbus::Error::FDO(error) => *error,
        error => fdo::Error::Failed(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_idle_daemon_counts_from_its_last_call() {
        let activity = Activity::new();
        {
            let _busy = activity.enter();
            assert_eq!(activity.idle_for(), Duration::ZERO);
        }
        assert!(!activity.busy());
    }
}

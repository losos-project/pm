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
    env::{self, split_paths},
    fs,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU64, AtomicUsize, Ordering},
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
    proxy::CacheProperties,
    zvariant::{OwnedObjectPath, Value},
};

use super::{
    ACTION_MANAGE_UNITS, ACTION_RUN, ACTION_UPDATE, BUS_NAME, INTERFACE, OBJECT_PATH,
    STARTED_SIGNAL, Verb,
    proxies::{AuthorityProxy, ManagerProxy, ServiceProxy, UnitProxy},
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

/// The variables a command run as root takes from its caller. Everything
/// else is the daemon's own or root's: a caller's `LD_PRELOAD` or `PATH` has
/// no business in a root process.
const PASSED_VARIABLES: [&str; 3] = ["TERM", "COLORTERM", "LANG"];

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
                    runs: AtomicU64::new(0),
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
    /// Numbers the transient units `Run` makes, with the daemon's pid, so two
    /// daemons in a row never pick the same name.
    runs: AtomicU64,
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

    /// Runs `argv` as root on the terminal `tty`, in `cwd`, and returns how it
    /// ended: systemd's `ExecMainCode` and `ExecMainStatus`.
    ///
    /// An empty `argv` runs root's login shell. `tty` must be a pseudo-terminal
    /// the caller owns: the client opens one and relays its own terminal to
    /// it, so the command never shares a terminal with the caller's session.
    /// The caller is sent `Started` once the command runs, and from then on
    /// the terminal is the command's.
    #[zbus(out_args("code", "status"))]
    async fn run(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] connection: &Connection,
        argv: Vec<String>,
        cwd: String,
        tty: String,
        env: HashMap<String, String>,
    ) -> fdo::Result<(i32, i32)> {
        let _busy = self.activity.enter();
        let caller = Caller::of(connection, &header).await?;
        check_terminal(&tty, caller.uid)?;
        let shell = root_shell();
        let argv = if argv.is_empty() {
            vec![shell.clone(), "-l".to_owned()]
        } else {
            argv
        };
        let program = resolve(&argv[0], &cwd)?;
        let command = shell_join(&argv);
        caller
            .authorize(
                connection,
                ACTION_RUN,
                HashMap::from([("command", command.as_str())]),
            )
            .await?;

        let name = format!(
            "pm-run-{}-{}.service",
            std::process::id(),
            self.runs.fetch_add(1, Ordering::SeqCst)
        );
        info!(
            uid = caller.uid,
            unit = name,
            command,
            "running a command as root"
        );
        let mut environment: Vec<String> = PASSED_VARIABLES
            .iter()
            .filter_map(|key| env.get(*key).map(|value| format!("{key}={value}")))
            .collect();
        environment.extend([
            format!("PATH={}", env::var("PATH").unwrap_or_default()),
            "HOME=/root".to_owned(),
            "USER=root".to_owned(),
            "LOGNAME=root".to_owned(),
            format!("SHELL={shell}"),
        ]);
        let directory = if cwd.starts_with('/') {
            // `-`: a folder root cannot enter is no reason not to run.
            format!("-{cwd}")
        } else {
            "/root".to_owned()
        };
        let description = format!("{command}, run as root by pm for uid {}", caller.uid);
        let exec_start = vec![(program.display().to_string(), argv, false)];
        let properties: Vec<(&str, Value<'_>)> = vec![
            ("Description", Value::from(description.as_str())),
            ("Type", Value::from("exec")),
            ("ExecStart", Value::from(exec_start)),
            ("User", Value::from("root")),
            ("WorkingDirectory", Value::from(directory.as_str())),
            ("Environment", Value::from(environment)),
            ("StandardInput", Value::from("tty")),
            ("StandardOutput", Value::from("tty")),
            ("StandardError", Value::from("tty")),
            ("TTYPath", Value::from(tty.as_str())),
            // The command's end is read after it exits, so the unit has to
            // outlive it: this connection holds a reference until `unref`.
            ("AddRef", Value::from(true)),
            ("CollectMode", Value::from("inactive-or-failed")),
            ("SendSIGHUP", Value::from(true)),
        ];

        let manager = ManagerProxy::new(connection).await.map_err(failed)?;
        subscribe(&manager).await;
        let mut removed = manager.receive_job_removed().await.map_err(failed)?;
        let job = manager
            .start_transient_unit(&name, "fail", &properties, &[])
            .await
            .map_err(failed)?;
        let path = manager.get_unit(&name).await.map_err(failed)?;
        let outcome = async {
            let result = job_result(&mut removed, &job).await?;
            if result != "done" {
                return Err(fdo::Error::Failed(format!(
                    "{command} did not start ({result}); journalctl -u {name} says why"
                )));
            }
            connection
                .emit_signal(
                    Some(caller.name.clone()),
                    OBJECT_PATH,
                    INTERFACE,
                    STARTED_SIGNAL,
                    &(name.as_str(),),
                )
                .await
                .map_err(failed)?;
            wait_for_exit(connection, &path).await
        }
        .await;
        // Whatever happened, the unit is let go of, or it would stay loaded
        // for as long as the daemon lives.
        if let Ok(unit) = unit_proxy(connection, &path).await
            && let Err(error) = unit.unref().await
        {
            warn!(unit = name, %error, "cannot release the unit");
        }
        let (code, status) = outcome?;
        info!(
            uid = caller.uid,
            unit = name,
            code,
            status,
            "the command ended"
        );
        Ok((code, status))
    }
}

/// Who sent a call: their unique bus name, which polkit identifies them by,
/// and their uid, which the logs and the terminal check use.
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

/// Waits for the unit at `path` to stop, and returns how its main process
/// ended.
async fn wait_for_exit(connection: &Connection, path: &OwnedObjectPath) -> fdo::Result<(i32, i32)> {
    let unit = unit_proxy(connection, path).await?;
    // The stream only wakes the loop; the state is read afresh each time, so
    // a change before the stream existed is not lost.
    let mut changes = fdo::PropertiesProxy::builder(connection)
        .destination("org.freedesktop.systemd1")?
        .path(path.as_ref())?
        .build()
        .await?
        .receive_properties_changed()
        .await?;
    loop {
        let state = unit.active_state().await.map_err(failed)?;
        if state == "inactive" || state == "failed" {
            break;
        }
        if changes.next().await.is_none() {
            return Err(fdo::Error::Failed(
                "lost systemd while the command ran".to_owned(),
            ));
        }
    }
    let service = ServiceProxy::builder(connection)
        .path(path.as_ref())?
        .cache_properties(CacheProperties::No)
        .build()
        .await?;
    Ok((
        service.exec_main_code().await.map_err(failed)?,
        service.exec_main_status().await.map_err(failed)?,
    ))
}

async fn unit_proxy<'a>(
    connection: &Connection,
    path: &'a OwnedObjectPath,
) -> fdo::Result<UnitProxy<'a>> {
    Ok(UnitProxy::builder(connection)
        .path(path.as_ref())?
        .cache_properties(CacheProperties::No)
        .build()
        .await?)
}

/// Refuses a terminal that is not one of the caller's pseudo-terminals, so
/// nobody can have root write to, or read from, a terminal of someone else's.
fn check_terminal(tty: &str, uid: u32) -> fdo::Result<()> {
    let numbered = tty
        .strip_prefix("/dev/pts/")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    let theirs = numbered
        && fs::metadata(tty)
            .is_ok_and(|meta| meta.file_type().is_char_device() && meta.uid() == uid);
    if theirs {
        Ok(())
    } else {
        Err(fdo::Error::InvalidArgs(format!(
            "{tty} is not a terminal of the caller's"
        )))
    }
}

/// Root's login shell, from the user database, or `/bin/sh`.
fn root_shell() -> String {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(0))
        .ok()
        .flatten()
        .map_or_else(
            || "/bin/sh".to_owned(),
            |root| root.shell.display().to_string(),
        )
}

/// Where the program `name` is: itself if it is absolute, under `cwd` if it
/// is a relative path, else the first match on the daemon's own `PATH`,
/// which is the one root's command gets.
///
/// A path is not looked for: it may be somewhere only root can see, such as
/// the caller's home, which the daemon is kept out of. systemd reports it
/// missing when the unit starts.
fn resolve(name: &str, cwd: &str) -> fdo::Result<PathBuf> {
    let found = if name.contains('/') {
        Some(Path::new(cwd).join(name)).filter(|path| path.is_absolute())
    } else {
        env::var_os("PATH").and_then(|path| {
            split_paths(&path)
                .map(|dir| dir.join(name))
                .find(|candidate| candidate.is_file())
        })
    };
    found.ok_or_else(|| fdo::Error::FileNotFound(format!("{name}: command not found")))
}

/// `argv` as a shell would need it typed, for the log and polkit's message.
fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| {
            let plain = !arg.is_empty()
                && arg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_./=:,+@%".contains(&b));
            if plain {
                arg.clone()
            } else {
                format!("'{}'", arg.replace('\'', r"'\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
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
    fn plain_arguments_are_not_quoted() {
        let argv = ["systemctl", "restart", "foo@bar.service"].map(str::to_owned);
        assert_eq!(shell_join(&argv), "systemctl restart foo@bar.service");
    }

    #[test]
    fn spaces_and_quotes_are_quoted() {
        let argv = ["sh", "-c", "echo 'hi' there", ""].map(str::to_owned);
        assert_eq!(shell_join(&argv), r"sh -c 'echo '\''hi'\'' there' ''");
    }

    #[test]
    fn only_numbered_pseudo_terminals_pass() {
        for tty in [
            "/dev/tty1",
            "/dev/pts/",
            "/dev/pts/ptmx",
            "/dev/pts/1/../../sda",
            "pts/1",
        ] {
            assert!(check_terminal(tty, 0).is_err(), "{tty}");
        }
    }

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

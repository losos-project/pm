//! `pm system`: the machine's administration, done by pm as its own user.
//!
//! An administrator does not become root to change the system. `pm system`
//! asks `pmd --system`, a service on the system bus that runs as the `pm`
//! user, and the daemon asks polkit whether the caller may. polkit asks the
//! caller to authenticate as an administrator, through their desktop's agent
//! or `pkttyagent` in a terminal, and only then does the daemon act - as `pm`,
//! through systemd, which the distribution's polkit rules let `pm` drive.
//!
//! So the `pm` user is the one identity the system trusts to manage units,
//! and the people who may use it are whoever polkit's rules name. Nothing here
//! is setuid, nothing holds a capability, and the daemon has no privilege the
//! rules do not give it.
//!
//! What the daemon does:
//!
//! * starts, stops, restarts and reloads units (`org.pm1.system.manage-units`);
//! * updates the operating system by starting `systemd-sysupdate.service`, and
//!   reboots into the update when asked (`org.pm1.system.update`);
//! * runs one command, or a shell, as root in a transient unit on a terminal
//!   the caller holds (`org.pm1.system.run`), which is what sudo, su and run0
//!   were for.
//!
//! The D-Bus policy and polkit actions it needs are in `data/`, and are the
//! distribution's to install along with a unit that runs `pmd --system` as
//! `pm`.

/// The client half: `pm system ...`.
pub mod client;
/// The service half: `pmd --system`.
pub mod daemon;
mod proxies;

/// The daemon's well-known name on the system bus.
pub const BUS_NAME: &str = "org.pm1.System";
/// The one object the daemon serves.
pub const OBJECT_PATH: &str = "/org/pm1/System";
/// Its interface.
pub const INTERFACE: &str = "org.pm1.System";
/// The signal [`daemon`] sends the caller of `Run`, and only them, once the
/// command has started, so the client knows the terminal is no longer the
/// authentication agent's.
pub const STARTED_SIGNAL: &str = "Started";

/// The polkit action for starting, stopping, restarting and reloading units.
pub const ACTION_MANAGE_UNITS: &str = "org.pm1.system.manage-units";
/// The polkit action for updating the system.
pub const ACTION_UPDATE: &str = "org.pm1.system.update";
/// The polkit action for running a command as root.
pub const ACTION_RUN: &str = "org.pm1.system.run";

/// What `Manage` can ask of a unit, as the daemon names it on the bus and to
/// polkit (`$(verb)` in the action's message).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Verb {
    /// Start the unit.
    Start,
    /// Stop it.
    Stop,
    /// Stop it if it runs, then start it.
    Restart,
    /// Ask it to reload its configuration.
    Reload,
}

impl Verb {
    /// The verb's name on the bus.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Reload => "reload",
        }
    }

    /// Parses a name [`Verb::as_str`] gave.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        [Self::Start, Self::Stop, Self::Restart, Self::Reload]
            .into_iter()
            .find(|verb| verb.as_str() == name)
    }
}

/// The unit name `name` stands for: itself when it has a unit type's suffix,
/// otherwise that name as a service, as systemctl reads it.
///
/// # Errors
///
/// The name is empty, too long, or holds a character systemd never allows in
/// one, which keeps a path or an option out of the daemon's calls.
pub fn unit_name(name: &str) -> Result<String, String> {
    const SUFFIXES: [&str; 11] = [
        ".service",
        ".socket",
        ".target",
        ".timer",
        ".path",
        ".mount",
        ".automount",
        ".swap",
        ".slice",
        ".scope",
        ".device",
    ];
    let allowed = |c: char| c.is_ascii_alphanumeric() || ":-_.\\@".contains(c);
    if name.is_empty() || name.len() > 255 || name.starts_with('-') || !name.chars().all(allowed) {
        return Err(format!("{name:?} is not a unit name"));
    }
    if SUFFIXES.iter().any(|suffix| name.ends_with(suffix)) {
        Ok(name.to_owned())
    } else {
        Ok(format!("{name}.service"))
    }
}

/// The exit status a shell would report for a process that ended as
/// systemd's `ExecMainCode` and `ExecMainStatus` say: its own status when it
/// exited, 128 and the signal when one killed it.
#[must_use]
pub const fn exit_status(code: i32, status: i32) -> i32 {
    /// `CLD_EXITED`, from `<signal.h>`.
    const CLD_EXITED: i32 = 1;
    if code == CLD_EXITED {
        status
    } else {
        128 + status
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_name_is_a_service() {
        assert_eq!(unit_name("sshd").unwrap(), "sshd.service");
        assert_eq!(unit_name("getty@tty1").unwrap(), "getty@tty1.service");
    }

    #[test]
    fn a_suffixed_name_is_kept() {
        assert_eq!(unit_name("multi-user.target").unwrap(), "multi-user.target");
        assert_eq!(unit_name("fstrim.timer").unwrap(), "fstrim.timer");
    }

    #[test]
    fn paths_options_and_spaces_are_not_unit_names() {
        for name in ["", "/etc/passwd", "--now", "a b", "a;b", "a\nb"] {
            assert!(unit_name(name).is_err(), "{name:?}");
        }
    }

    #[test]
    fn verbs_round_trip() {
        for verb in [Verb::Start, Verb::Stop, Verb::Restart, Verb::Reload] {
            assert_eq!(Verb::from_name(verb.as_str()), Some(verb));
        }
        assert_eq!(Verb::from_name("enable"), None);
    }

    #[test]
    fn a_signal_reads_as_a_shell_would_report_it() {
        assert_eq!(exit_status(1, 3), 3);
        assert_eq!(exit_status(2, 9), 137);
        assert_eq!(exit_status(3, 11), 139);
    }
}

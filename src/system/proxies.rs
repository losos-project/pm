//! The system services `pmd --system` talks to, as pm: systemd's manager and
//! units, and polkit's authority.
//!
//! Only the members the daemon calls are declared. Each trait expands to an
//! async proxy, which the daemon's interface methods await, and a blocking
//! one nobody uses.

use std::collections::HashMap;

use zbus::{
    proxy,
    zvariant::{ObjectPath, OwnedObjectPath, Value},
};

/// `org.freedesktop.systemd1.Manager`, the system manager.
#[proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1"
)]
pub trait Manager {
    /// Asks systemd to send this connection its job and unit signals.
    /// Without it, `JobRemoved` and a unit's `PropertiesChanged` may never
    /// arrive.
    fn subscribe(&self) -> zbus::Result<()>;

    fn start_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    fn stop_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    fn restart_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;
    fn reload_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;

    /// Creates a unit from `properties` and starts it.
    fn start_transient_unit(
        &self,
        name: &str,
        mode: &str,
        properties: &[(&str, Value<'_>)],
        aux: &[(&str, &[(&str, Value<'_>)])],
    ) -> zbus::Result<OwnedObjectPath>;

    fn get_unit(&self, name: &str) -> zbus::Result<OwnedObjectPath>;

    /// A job finished; `result` is `done` when it did what it was asked.
    #[zbus(signal)]
    fn job_removed(
        &self,
        id: u32,
        job: ObjectPath<'_>,
        unit: &str,
        result: &str,
    ) -> zbus::Result<()>;
}

/// `org.freedesktop.systemd1.Unit`, one loaded unit.
#[proxy(
    interface = "org.freedesktop.systemd1.Unit",
    default_service = "org.freedesktop.systemd1"
)]
pub trait Unit {
    /// Drops the reference `AddRef=yes` took for this connection, so the unit
    /// can be collected.
    fn unref(&self) -> zbus::Result<()>;

    #[zbus(property)]
    fn active_state(&self) -> zbus::Result<String>;
}

/// `org.freedesktop.systemd1.Service`, the service half of a unit.
#[proxy(
    interface = "org.freedesktop.systemd1.Service",
    default_service = "org.freedesktop.systemd1"
)]
pub trait Service {
    /// How the main process ended: `CLD_EXITED` (1), `CLD_KILLED` (2) or
    /// `CLD_DUMPED` (3).
    #[zbus(property)]
    fn exec_main_code(&self) -> zbus::Result<i32>;

    /// Its exit status, or the signal that ended it.
    #[zbus(property)]
    fn exec_main_status(&self) -> zbus::Result<i32>;
}

/// `org.freedesktop.PolicyKit1.Authority`.
#[proxy(
    interface = "org.freedesktop.PolicyKit1.Authority",
    default_service = "org.freedesktop.PolicyKit1",
    default_path = "/org/freedesktop/PolicyKit1/Authority"
)]
pub trait Authority {
    /// Whether `subject` may do `action_id`, asking them to authenticate first
    /// when `flags` has bit 0 set and the action calls for it.
    fn check_authorization(
        &self,
        subject: &(&str, HashMap<&str, Value<'_>>),
        action_id: &str,
        details: &HashMap<&str, &str>,
        flags: u32,
        cancellation_id: &str,
    ) -> zbus::Result<(bool, bool, HashMap<String, String>)>;
}

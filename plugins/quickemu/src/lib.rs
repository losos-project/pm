//! A pm plugin that manages a user's machines, for `pm machine`, with quickemu.
//!
//! A machine is a quickemu virtual machine: a `<name>.conf` that quickemu reads,
//! beside a folder holding the machine's disk, its firmware's variables, its TPM's
//! state and, once it runs, the sockets that drive it. pm's own record of it,
//! `machine.json`, sits in the same folder, so everything a machine is lives in its
//! owner's files and nothing else keeps a second copy: no daemon, no definition
//! held elsewhere. [`machines`] says where each thing goes.
//!
//! A machine runs as a systemd service of its owner's, `pm-machine-<name>`, which
//! `systemd-run` starts around `quickemu --vm`: quickemu starts QEMU and leaves, and
//! the service lasts as long as QEMU does. Stopping it is quickemu's too, through
//! the QEMU monitor socket beside the disk.
//!
//! The plugin only writes files and command lines. It reaches nothing: like every pm
//! plugin it runs in a metered WebAssembly instance whose one import is `log`, and
//! what it can make pm run is [`LAUNCHERS`], which `pm plugins` prints.
//!
//! It boots no package's own kernel: `launch-machine` declines, and pm starts QEMU
//! for one itself.

wit_bindgen::generate!({ path: "../../wit", world: "machine-plugin" });

mod machines;

struct Quickemu;

/// Every program the plugin may have pm run.
pub(crate) const LAUNCHERS: [&str; 11] = [
    "chmod",
    "cp",
    "find",
    "mkdir",
    "mv",
    "qemu-img",
    "quickemu",
    "rm",
    "systemctl",
    "systemd-run",
    "test",
];

impl Guest for Quickemu {
    fn describe() -> Manifest {
        Manifest {
            name: "quickemu".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            summary: "Manages each user's machines with quickemu, as services of their own".into(),
            hooks: Vec::new(),
            grants_at_most: Vec::new(),
            source_extensions: Vec::new(),
            symbols: Vec::new(),
        }
    }

    // It classifies nothing and scans nothing: `hooks` is empty, so pm never calls
    // these, but the `plugin` world every world includes still exports them.
    fn classify_command(_command: String) -> Option<Verdict> {
        None
    }

    fn scan_source(_file: SourceFile) -> Vec<Grant> {
        Vec::new()
    }

    fn launchers() -> Vec<String> {
        LAUNCHERS.map(Into::into).to_vec()
    }

    fn machine_plan(
        request: MachineRequest,
        place: MachinePlace,
    ) -> Result<Vec<MachineStep>, String> {
        machines::steps(request, &place)
    }

    fn launch_machine(_machine: Machine) -> Result<Option<Launch>, String> {
        Ok(None)
    }
}

export!(Quickemu);

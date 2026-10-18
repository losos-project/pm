//! A pm plugin that boots a package's own kernel through libvirt.
//!
//! A package built with `kernel = kernel(image = ...)` runs in a virtual machine. pm
//! starts QEMU for it itself unless a `vm-plugin` answers first; this one answers
//! with `virsh create`, so the machine is libvirt's: it shows up in `virsh list` and
//! virt-manager while it runs, under the title `pm run: <entrypoint>`, and QEMU runs
//! wherever libvirt runs it, as its own user in the system daemon, confined by its
//! security driver.
//!
//! # Why `virsh create --console --autodestroy`
//!
//! pm's launcher contract is that the program lives exactly as long as the machine
//! and owns its console (see `pm_vm::launch`). This one command does both:
//!
//! * `create` starts a transient domain from the XML written beside the machine, so
//!   nothing is left defined once it stops.
//! * `--console` attaches to the guest's first serial port and returns when the
//!   guest powers off, which is what pm's init does once the entrypoint exits.
//! * `--autodestroy` ties the domain to virsh's connection, so if virsh dies - pm
//!   sends it `SIGTERM` when pm dies - libvirt destroys the machine rather than
//!   leaving it running with nobody attached.
//!
//! virsh connects where libvirt's own rules say: `LIBVIRT_DEFAULT_URI` when it is
//! set, otherwise `qemu:///system` for root and for anyone polkit lets manage it, and
//! `qemu:///session` for everyone else. The plugin passes no `-c`, so whichever
//! libvirt the user already drives virt-manager with is the one pm uses.
//!
//! # `pm machine`
//!
//! It also manages the host's persistent machines, in the `machine-plugin` world: see
//! [`machines`]. They are libvirt's too, in the `default` storage pool and on the
//! `default` network, so virsh, virt-manager and a desktop that talks to libvirt see
//! the same machines pm made.
//!
//! Every user who asks reaches those same machines, the daemon's, so the
//! [`MachinePlace`] pm passes is not used: it is for a plugin like `quickemu`, which
//! keeps each user's machines in that user's files. With both installed, pm asks the
//! first in file-name order, which is this one.
//!
//! The plugin only writes XML and command lines. It reaches nothing: like every pm
//! plugin it runs in a metered WebAssembly instance whose one import is `log`, and the
//! one program it can make pm run is `virsh`, which `pm plugins` prints.

wit_bindgen::generate!({ path: "../../wit", world: "machine-plugin" });

mod machines;

use pm::plugin::types::LaunchFile;

struct Libvirt;

/// The program the plugin launches; the only one in `launchers`.
const VIRSH: &str = "virsh";

/// The file name the domain definition is written under, in the machine's directory.
const DOMAIN_XML: &str = "domain.xml";

impl Guest for Libvirt {
    fn describe() -> Manifest {
        Manifest {
            name: "libvirt".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            summary: "Boots a package's own kernel, and manages the host's machines, through libvirt's virsh".into(),
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
        vec![VIRSH.into()]
    }

    // libvirt's machines are its daemon's, wherever the person asking keeps their
    // files, so the place pm gives says nothing this plugin needs.
    fn machine_plan(
        request: MachineRequest,
        _place: MachinePlace,
    ) -> Result<Vec<MachineStep>, String> {
        machines::steps(request)
    }

    fn launch_machine(machine: Machine) -> Result<Option<Launch>, String> {
        let domain = domain_xml(&machine);
        Ok(Some(Launch {
            program: VIRSH.into(),
            args: vec![
                // No greeting ("Connected to domain...") or escape-key hint on the
                // console pm hands the user: they see the guest's output and nothing
                // else, as under pm's own QEMU.
                "-q".into(),
                "create".into(),
                "--console".into(),
                "--autodestroy".into(),
                format!("{}/{DOMAIN_XML}", machine.directory),
            ],
            files: vec![LaunchFile {
                name: DOMAIN_XML.into(),
                contents: domain,
            }],
        }))
    }
}

/// The transient domain the machine runs as.
///
/// It mirrors what pm passes QEMU when it starts it itself: direct kernel boot of
/// pm's kernel and initramfs with pm's command line, the console on the first serial
/// port and init's report on the second, and no other devices - no disk, no network,
/// no USB, no balloon - because the guest has nothing but its initramfs and pm's
/// jail gave the package no network either.
fn domain_xml(machine: &Machine) -> String {
    // Without KVM libvirt still boots the machine, under TCG, as pm's QEMU does.
    let (kind, cpu) = if machine.kvm {
        ("kvm", "\n  <cpu mode='host-passthrough'/>")
    } else {
        ("qemu", "")
    };
    format!(
        "<domain type='{kind}'>
  <name>{name}</name>
  <title>{title}</title>
  <memory unit='MiB'>{memory}</memory>
  <vcpu>{cpus}</vcpu>
  <os>
    <type arch='x86_64' machine='pc'>hvm</type>
    <kernel>{kernel}</kernel>
    <initrd>{initramfs}</initrd>
    <cmdline>{cmdline}</cmdline>
  </os>
  <features>
    <!-- libvirt leaves ACPI off unless asked, and without it the guest's power-off
         only halts the CPU: the machine never stops and virsh never returns. -->
    <acpi/>
  </features>{cpu}
  <!-- Whatever ends the guest ends the machine; a transient domain that rebooted
       would run the entrypoint a second time. -->
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>destroy</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <!-- The console: a pty, because that is what virsh attaches its console to. -->
    <serial type='pty'>
      <target port='0'/>
    </serial>
    <!-- Init's exit report, to the socket pm listens on. libvirt hands QEMU the
         connected socket, so QEMU need not be able to open pm's directory itself. -->
    <serial type='unix'>
      <source mode='connect' path='{status}'/>
      <target port='1'/>
    </serial>
    <controller type='usb' model='none'/>
    <memballoon model='none'/>
  </devices>
</domain>
",
        name = escape(&machine.name),
        title = escape(&machine.title),
        memory = machine.memory_mib,
        cpus = machine.cpus,
        kernel = escape(&machine.kernel),
        initramfs = escape(&machine.initramfs),
        cmdline = escape(&machine.cmdline),
        status = escape(&machine.status_socket),
    )
}

/// `text` as XML character data or a single-quoted attribute value. Shared with
/// [`machines`].
///
/// The entrypoint's name reaches the title and the command line, and a package names
/// its own entrypoints, so every string is escaped, not only the ones that look like
/// they could hold markup.
pub(crate) fn escape(text: &str) -> String {
    text.chars()
        .fold(String::with_capacity(text.len()), |mut out, c| {
            match c {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '\'' => out.push_str("&apos;"),
                '"' => out.push_str("&quot;"),
                c => out.push(c),
            }
            out
        })
}

export!(Libvirt);

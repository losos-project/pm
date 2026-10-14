//! `pm machine`: the host's persistent machines, as libvirt's.
//!
//! Every request becomes a few `virsh` commands against the default connection,
//! which on LosOS is `qemu:///system` for everyone (libvirt's `uri_default`), so the
//! machines pm makes are the ones the desktop, virsh and virt-manager see.
//!
//! # Where things go
//!
//! * A **template** is a read-only volume in the `default` storage pool, named
//!   `pm-template-<name>-<digest>.<format>`: the image's own digest is in the name,
//!   so a changed image is a new template beside the old one, and the machines on
//!   the old one keep it.
//! * A machine's **disk** is a qcow2 volume in the same pool,
//!   `pm-machine-<name>.qcow2`, backed by its template: it holds only what the
//!   machine has written.
//! * The machine itself is a persistent domain called `<name>`, on the `default`
//!   network, with its [label](LABEL_NAMESPACE) and template in `<metadata>`, a vsock
//!   device whose address libvirt picks, and a channel for the QEMU guest agent.
//!   The vsock and the agent are how a desktop shows the guest's windows and starts
//!   programs in it; a guest that runs neither still boots.

use crate::{
    MachineRequest, MachineStep, VIRSH, escape,
    pm::plugin::types::{
        DiskFormat, Firmware, Launch, LaunchFile, MachineLabel, MachineSpec, MachineTemplate,
    },
};

/// The storage pool templates and disks live in: the one libvirt and virt-manager
/// use when told nothing else.
const POOL: &str = "default";

/// The network machines are on: libvirt's own NAT network.
const NETWORK: &str = "default";

/// The XML namespace of what pm records in a machine's `<metadata>`. A desktop reads
/// the label from there to frame the machine's windows.
pub(crate) const LABEL_NAMESPACE: &str = "https://losos-project.github.io/xmlns/pm-machine/1";

/// The steps that carry `request` out.
pub(crate) fn steps(request: MachineRequest) -> Result<Vec<MachineStep>, String> {
    Ok(match request {
        MachineRequest::Create(spec) => create(&spec)?,
        // Not `-q`, which for `list` drops the table's header too.
        MachineRequest::List => vec![step(
            "list the machines",
            Launch {
                program: VIRSH.into(),
                args: ["list", "--all", "--title"].map(Into::into).to_vec(),
                files: Vec::new(),
            },
        )],
        MachineRequest::Start(name) => vec![MachineStep {
            unless: Some(running(&name)),
            ..step(
                &format!("start the machine {name}"),
                virsh(&["start", &name]),
            )
        }],
        MachineRequest::Stop(name) => vec![MachineStep {
            when: Some(running(&name)),
            ..step(
                &format!("ask the machine {name} to shut down"),
                virsh(&["shutdown", &name]),
            )
        }],
        MachineRequest::Kill(name) => vec![MachineStep {
            when: Some(running(&name)),
            ..step(
                &format!("power off the machine {name}"),
                virsh(&["destroy", &name]),
            )
        }],
        MachineRequest::Remove(name) => vec![
            MachineStep {
                when: Some(running(&name)),
                ..step(
                    &format!("power off the machine {name}"),
                    virsh(&["destroy", &name]),
                )
            },
            // `--remove-all-storage` deletes the volumes the domain's disks name -
            // its own copy-on-write disk - and never the template under it, which
            // other machines may be on. `--nvram` deletes the UEFI variables
            // libvirt keeps for it, which would otherwise greet the next machine of
            // the same name.
            step(
                &format!("delete the machine {name} and its disk"),
                virsh(&["undefine", &name, "--nvram", "--remove-all-storage"]),
            ),
        ],
    })
}

/// Install the template unless it is installed, give the machine a disk on top of
/// it, and define the machine.
fn create(spec: &MachineSpec) -> Result<Vec<MachineStep>, String> {
    let template = &spec.template;
    let format = format_name(template.format);
    let template_volume = template_volume(template);
    let disk_volume = format!("pm-machine-{}.qcow2", spec.name);
    let domain = domain_xml(spec, &disk_volume)?;

    let installed = virsh(&["vol-info", "--pool", POOL, &template_volume]);
    let forget_template = virsh(&["vol-delete", "--pool", POOL, &template_volume]);
    Ok(vec![
        // A volume of the image's own length and format, which the upload then
        // overwrites byte for byte: libvirt has no "import this file" for a pool,
        // and uploading is what lets a daemon running as another user own the
        // result without reading the user's files.
        MachineStep {
            unless: Some(installed.clone()),
            undo: Some(forget_template.clone()),
            ..step(
                &format!("install the template {}", template.name),
                virsh(&[
                    "vol-create-as",
                    POOL,
                    &template_volume,
                    &format!("{}B", template.file_size),
                    "--format",
                    format,
                ]),
            )
        },
        MachineStep {
            unless: Some(installed.clone()),
            undo: Some(forget_template),
            ..step(
                &format!("upload {}", template.image),
                virsh(&[
                    "vol-upload",
                    "--pool",
                    POOL,
                    &template_volume,
                    &template.image,
                    // Holes in a raw image stay holes in the pool.
                    "--sparse",
                ]),
            )
        },
        // The volume's size and format are what its first bytes say, and libvirt
        // reads them again only when it looks at the pool again.
        MachineStep {
            unless: Some(installed),
            ..step(
                &format!("refresh the {POOL} pool"),
                virsh(&["pool-refresh", POOL]),
            )
        },
        MachineStep {
            undo: Some(virsh(&["vol-delete", "--pool", POOL, &disk_volume])),
            ..step(
                &format!("make the disk of the machine {}", spec.name),
                virsh(&[
                    "vol-create-as",
                    POOL,
                    &disk_volume,
                    &format!("{}B", spec.disk_size),
                    "--format",
                    "qcow2",
                    "--backing-vol",
                    &template_volume,
                    "--backing-vol-format",
                    format,
                ]),
            )
        },
        MachineStep {
            undo: Some(virsh(&["undefine", &spec.name, "--nvram"])),
            ..step(
                &format!("define the machine {}", spec.name),
                Launch {
                    files: vec![LaunchFile {
                        name: DOMAIN_XML.into(),
                        contents: domain,
                    }],
                    ..virsh(&["define", DOMAIN_XML])
                },
            )
        },
    ])
}

/// The file the definition is written to, in the step's own directory.
const DOMAIN_XML: &str = "domain.xml";

/// The template's volume name: its name, then enough of its digest that two images
/// of one name never share a volume.
fn template_volume(template: &MachineTemplate) -> String {
    let digest: String = template.digest.chars().take(16).collect();
    format!(
        "pm-template-{}-{digest}.{}",
        template.name,
        format_name(template.format)
    )
}

const fn format_name(format: DiskFormat) -> &'static str {
    match format {
        DiskFormat::Raw => "raw",
        DiskFormat::Qcow2 => "qcow2",
    }
}

pub(crate) const fn label_name(label: MachineLabel) -> &'static str {
    match label {
        MachineLabel::Red => "red",
        MachineLabel::Orange => "orange",
        MachineLabel::Yellow => "yellow",
        MachineLabel::Green => "green",
        MachineLabel::Gray => "gray",
        MachineLabel::Blue => "blue",
        MachineLabel::Purple => "purple",
        MachineLabel::Black => "black",
    }
}

/// The machine's persistent definition.
///
/// A modern PC (q35) on x86-64 and QEMU's `virt` board on arm64, both with UEFI
/// unless the template boots from a BIOS, and nothing a desktop guest does not use:
/// no graphics card, because its windows reach the host's desktop over vsock rather
/// than through an emulated screen, and no USB controller, because nothing is
/// plugged into it until its owner says so.
fn domain_xml(spec: &MachineSpec, disk_volume: &str) -> Result<String, String> {
    let template = &spec.template;
    let (arch, board) = match spec.arch.as_str() {
        "x86_64" => ("x86_64", "q35"),
        "aarch64" => ("aarch64", "virt"),
        other => return Err(format!("libvirt machines on {other} are not supported")),
    };
    let firmware = match (template.firmware, arch) {
        // libvirt picks the firmware file itself, from the descriptors QEMU
        // installs, and keeps the machine's own copy of the variables. Secure
        // Boot is off: the template's boot loader is whatever its maker signed it
        // with, if anything, and the host's keys would refuse it.
        (Firmware::Uefi, _) => {
            " firmware='efi'>\n    <firmware>\n      <feature enabled='no' name='secure-boot'/>\n    </firmware"
        }
        (Firmware::Bios, "x86_64") => "",
        (Firmware::Bios, _) => return Err(format!("an {arch} machine cannot boot from a BIOS")),
    };
    let (kind, cpu) = if spec.kvm {
        ("kvm", "host-passthrough")
    } else {
        // Without KVM, QEMU emulates the processor; `maximum` gives the guest every
        // feature it can emulate, which is what an arm64 machine needs to have a
        // CPU at all.
        ("qemu", "maximum")
    };
    let features = if arch == "x86_64" {
        "<acpi/>\n    <apic/>"
    } else {
        "<acpi/>\n    <gic version='3'/>"
    };
    Ok(format!(
        "<domain type='{kind}'>
  <name>{name}</name>
  <title>{title}</title>
  <metadata>
    <pm:machine xmlns:pm='{LABEL_NAMESPACE}'>
      <pm:label>{label}</pm:label>
      <pm:template name='{template_name}' digest='{digest}'/>
    </pm:machine>
  </metadata>
  <memory unit='MiB'>{memory}</memory>
  <vcpu>{cpus}</vcpu>
  <os{firmware}>
    <type arch='{arch}' machine='{board}'>hvm</type>
  </os>
  <features>
    {features}
  </features>
  <cpu mode='{cpu}'/>
  <clock offset='utc'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <disk type='volume' device='disk'>
      <!-- discard='unmap' hands what the guest frees back to the pool. -->
      <driver name='qemu' type='qcow2' discard='unmap'/>
      <source pool='{POOL}' volume='{disk}'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <interface type='network'>
      <source network='{NETWORK}'/>
      <model type='virtio'/>
    </interface>
    <!-- The QEMU guest agent: how the host starts a program in the guest. -->
    <channel type='unix'>
      <target type='virtio' name='org.qemu.guest_agent.0'/>
    </channel>
    <!-- How the guest's windows reach the host's desktop. libvirt picks the
         address, and the host knows which machine an address is from libvirt
         alone, since the guest cannot choose its own. -->
    <vsock model='virtio'>
      <cid auto='yes'/>
    </vsock>
    <serial type='pty'>
      <target port='0'/>
    </serial>
    <console type='pty'/>
    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
    </rng>
    <memballoon model='virtio'/>
    <controller type='usb' model='none'/>
  </devices>
</domain>
",
        name = escape(&spec.name),
        title = escape(&format!(
            "{}, from {}",
            label_name(spec.label),
            template.name
        )),
        label = label_name(spec.label),
        template_name = escape(&template.name),
        digest = escape(&template.digest),
        memory = spec.memory_mib,
        cpus = spec.cpus,
        disk = escape(disk_volume),
    ))
}

/// A step that only runs `launch`.
fn step(summary: &str, run: Launch) -> MachineStep {
    MachineStep {
        summary: summary.into(),
        run,
        when: None,
        unless: None,
        undo: None,
    }
}

fn virsh(args: &[&str]) -> Launch {
    Launch {
        program: VIRSH.into(),
        // `-q` drops virsh's chatter ("Domain 'work' started"): pm logs each
        // step's summary itself.
        args: ["-q"]
            .into_iter()
            .chain(args.iter().copied())
            .map(Into::into)
            .collect(),
        files: Vec::new(),
    }
}

/// A probe that succeeds while `name` runs.
///
/// `virsh domjobinfo` asks about a running machine's background job and fails for a
/// machine that is not running, which makes its exit status the one plain yes or no
/// virsh gives to "is it running?": `domstate` and `domid` both succeed either way.
fn running(name: &str) -> Launch {
    virsh(&["domjobinfo", name])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(arch: &str, kvm: bool, firmware: Firmware) -> MachineSpec {
        MachineSpec {
            name: "work".into(),
            label: MachineLabel::Blue,
            template: MachineTemplate {
                name: "losos-guest".into(),
                digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                image: "/usr/share/losos/machines/losos-guest.qcow2".into(),
                format: DiskFormat::Qcow2,
                file_size: 1 << 30,
                disk_size: 8 << 30,
                firmware,
            },
            disk_size: 32 << 30,
            memory_mib: 2048,
            cpus: 2,
            kvm,
            arch: arch.into(),
        }
    }

    fn args(launch: &Launch) -> String {
        assert_eq!(launch.program, "virsh");
        launch.args.join(" ")
    }

    #[test]
    fn create_installs_the_template_once_then_makes_the_machine() {
        let steps = steps(MachineRequest::Create(spec("x86_64", true, Firmware::Uefi))).unwrap();
        let runs: Vec<String> = steps.iter().map(|step| args(&step.run)).collect();
        let template = "pm-template-losos-guest-0123456789abcdef.qcow2";
        assert_eq!(
            runs,
            [
                format!("-q vol-create-as default {template} 1073741824B --format qcow2"),
                format!(
                    "-q vol-upload --pool default {template} \
                     /usr/share/losos/machines/losos-guest.qcow2 --sparse"
                ),
                "-q pool-refresh default".into(),
                format!(
                    "-q vol-create-as default pm-machine-work.qcow2 34359738368B --format qcow2 \
                     --backing-vol {template} --backing-vol-format qcow2"
                ),
                "-q define domain.xml".into(),
            ]
        );
        // The template's three steps are skipped together when it is there already.
        for step in &steps[..3] {
            assert_eq!(
                args(step.unless.as_ref().unwrap()),
                format!("-q vol-info --pool default {template}")
            );
        }
        // And the machine's own two are always taken back if a later one fails.
        assert_eq!(
            args(steps[3].undo.as_ref().unwrap()),
            "-q vol-delete --pool default pm-machine-work.qcow2"
        );
        assert_eq!(
            args(steps[4].undo.as_ref().unwrap()),
            "-q undefine work --nvram"
        );
        assert!(steps[3].unless.is_none() && steps[4].unless.is_none());
    }

    #[test]
    fn the_definition_carries_the_label_vsock_and_agent() {
        let steps = steps(MachineRequest::Create(spec("x86_64", true, Firmware::Uefi))).unwrap();
        let [file] = steps[4].run.files.as_slice() else {
            panic!("one file");
        };
        let xml = &file.contents;
        for expected in [
            "<domain type='kvm'>",
            "<name>work</name>",
            "<title>blue, from losos-guest</title>",
            "<pm:label>blue</pm:label>",
            "<pm:template name='losos-guest' digest='0123456789abcdef",
            "<os firmware='efi'>",
            "<feature enabled='no' name='secure-boot'/>",
            "<type arch='x86_64' machine='q35'>hvm</type>",
            "<cpu mode='host-passthrough'/>",
            "<source pool='default' volume='pm-machine-work.qcow2'/>",
            "<source network='default'/>",
            "name='org.qemu.guest_agent.0'",
            "<cid auto='yes'/>",
            "<memory unit='MiB'>2048</memory>",
            "<vcpu>2</vcpu>",
        ] {
            assert!(xml.contains(expected), "{expected} in\n{xml}");
        }
        // An XML comment cannot hold `--`.
        for comment in xml.split("<!--").skip(1) {
            let body = comment.split("-->").next().unwrap();
            assert!(!body.contains("--"), "{body}");
        }
    }

    #[test]
    fn without_kvm_the_processor_is_emulated() {
        let steps = steps(MachineRequest::Create(spec(
            "aarch64",
            false,
            Firmware::Uefi,
        )))
        .unwrap();
        let xml = &steps[4].run.files[0].contents;
        assert!(xml.contains("<domain type='qemu'>"));
        assert!(xml.contains("<cpu mode='maximum'/>"));
        assert!(xml.contains("<type arch='aarch64' machine='virt'>hvm</type>"));
        assert!(xml.contains("<gic version='3'/>"));
    }

    #[test]
    fn a_bios_template_boots_without_uefi_but_only_on_a_pc() {
        let steps = steps(MachineRequest::Create(spec("x86_64", true, Firmware::Bios))).unwrap();
        let xml = &steps[4].run.files[0].contents;
        assert!(xml.contains("  <os>\n"));
        assert!(!xml.contains("firmware="));
        assert!(steps_for(spec("aarch64", true, Firmware::Bios)).is_err());
        assert!(steps_for(spec("riscv64", true, Firmware::Uefi)).is_err());
    }

    fn steps_for(spec: MachineSpec) -> Result<Vec<MachineStep>, String> {
        steps(MachineRequest::Create(spec))
    }

    #[test]
    fn lifecycle_requests_ask_whether_the_machine_runs() {
        let one = |request| {
            let mut steps = steps(request).unwrap();
            assert_eq!(steps.len(), 1);
            steps.remove(0)
        };
        let start = one(MachineRequest::Start("work".into()));
        assert_eq!(args(&start.run), "-q start work");
        assert_eq!(args(start.unless.as_ref().unwrap()), "-q domjobinfo work");

        let stop = one(MachineRequest::Stop("work".into()));
        assert_eq!(args(&stop.run), "-q shutdown work");
        assert_eq!(args(stop.when.as_ref().unwrap()), "-q domjobinfo work");

        let kill = one(MachineRequest::Kill("work".into()));
        assert_eq!(args(&kill.run), "-q destroy work");
        assert_eq!(args(kill.when.as_ref().unwrap()), "-q domjobinfo work");

        assert_eq!(args(&one(MachineRequest::List).run), "list --all --title");
    }

    #[test]
    fn remove_powers_off_then_deletes_the_disk_but_not_the_template() {
        let steps = steps(MachineRequest::Remove("work".into())).unwrap();
        assert_eq!(args(&steps[0].run), "-q destroy work");
        assert!(steps[0].when.is_some());
        assert_eq!(
            args(&steps[1].run),
            "-q undefine work --nvram --remove-all-storage"
        );
        assert!(steps[1].when.is_none() && steps[1].undo.is_none());
    }
}

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
//! * A **CD** a machine installs its system from is a read-only volume beside
//!   them, `pm-media-<name>-<digest>.iso`, shared the same way by every machine
//!   given it. Such a machine's disk starts empty, `pm-machine-<name>.qcow2` with
//!   nothing under it.
//! * The machine itself is a persistent domain called `<name>`, on the `default`
//!   network, with its [label](LABEL_NAMESPACE) and template or system in
//!   `<metadata>`, a vsock device whose address libvirt picks, and a channel for
//!   the QEMU guest agent. The vsock and the agent are how a desktop shows the
//!   guest's windows and starts programs in it; a guest that runs neither still
//!   boots. A machine that installs from CDs also has a screen, since its
//!   installer has no other way to be seen, and a Windows one has no vsock, which
//!   Windows has no use for, and instead what Windows wants of a PC: Hyper-V's
//!   enlightenments, a TPM and its clock in local time.

use crate::{
    MachineRequest, MachineStep, VIRSH, escape,
    pm::plugin::types::{
        DiskFormat, Firmware, GuestSystem, Launch, LaunchFile, MachineLabel, MachineMedia,
        MachineSource, MachineSpec, MachineTemplate,
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

/// The steps that carry `request` out, on a host whose first GPU render node is
/// `render_node`, if it has a GPU.
pub(crate) fn steps(
    request: MachineRequest,
    render_node: Option<&str>,
) -> Result<Vec<MachineStep>, String> {
    Ok(match request {
        MachineRequest::Create(spec) => create(&spec, render_node)?,
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
            // `--storage vda` deletes the machine's own disk and nothing else: not
            // the template under it, and not its CDs, which other machines may be
            // given too and which `--remove-all-storage` would take with it.
            // `--nvram` deletes the UEFI variables libvirt keeps for it, which
            // would otherwise greet the next machine of the same name; a TPM's
            // state goes with the machine unasked.
            step(
                &format!("delete the machine {name} and its disk"),
                virsh(&["undefine", &name, "--nvram", "--storage", DISK_TARGET]),
            ),
        ],
    })
}

/// Install the template or CDs that are not installed, give the machine a disk,
/// and define the machine.
fn create(spec: &MachineSpec, render_node: Option<&str>) -> Result<Vec<MachineStep>, String> {
    let disk_volume = format!("pm-machine-{}.qcow2", spec.name);
    let domain = domain_xml(spec, &disk_volume, render_node)?;
    let mut steps = Vec::new();
    let make_disk = match &spec.source {
        MachineSource::Template(template) => {
            let volume = template_volume(template);
            let format = format_name(template.format);
            steps.extend(install(
                &format!("the template {}", template.name),
                &volume,
                &template.image,
                template.file_size,
                format,
            ));
            virsh(&[
                "vol-create-as",
                POOL,
                &disk_volume,
                &format!("{}B", spec.disk_size),
                "--format",
                "qcow2",
                "--backing-vol",
                &volume,
                "--backing-vol-format",
                format,
            ])
        }
        MachineSource::Installer(installer) => {
            for media in &installer.media {
                steps.extend(install(
                    &format!("the CD {}", media.name),
                    &media_volume(media),
                    &media.image,
                    media.file_size,
                    "raw",
                ));
            }
            virsh(&[
                "vol-create-as",
                POOL,
                &disk_volume,
                &format!("{}B", spec.disk_size),
                "--format",
                "qcow2",
            ])
        }
    };
    steps.extend([
        MachineStep {
            undo: Some(virsh(&["vol-delete", "--pool", POOL, &disk_volume])),
            ..step(
                &format!("make the disk of the machine {}", spec.name),
                make_disk,
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
    ]);
    Ok(steps)
}

/// The steps that put `image` into the pool as `volume`, each skipped when the
/// volume is there already.
fn install(
    what: &str,
    volume: &str,
    image: &str,
    file_size: u64,
    format: &str,
) -> [MachineStep; 3] {
    let installed = virsh(&["vol-info", "--pool", POOL, volume]);
    let forget = virsh(&["vol-delete", "--pool", POOL, volume]);
    [
        // A volume of the image's own length and format, which the upload then
        // overwrites byte for byte: libvirt has no "import this file" for a pool,
        // and uploading is what lets a daemon running as another user own the
        // result without reading the user's files.
        MachineStep {
            unless: Some(installed.clone()),
            undo: Some(forget.clone()),
            ..step(
                &format!("install {what}"),
                virsh(&[
                    "vol-create-as",
                    POOL,
                    volume,
                    &format!("{file_size}B"),
                    "--format",
                    format,
                ]),
            )
        },
        MachineStep {
            unless: Some(installed.clone()),
            undo: Some(forget),
            ..step(
                &format!("upload {image}"),
                virsh(&[
                    "vol-upload",
                    "--pool",
                    POOL,
                    volume,
                    image,
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
    ]
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

/// A CD's volume name, made as a template's is.
fn media_volume(media: &MachineMedia) -> String {
    let digest: String = media.digest.chars().take(16).collect();
    format!("pm-media-{}-{digest}.iso", media.name)
}

/// The machine's own disk, as the guest sees it: the one `remove` deletes.
const DISK_TARGET: &str = "vda";

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
/// unless the template boots from a BIOS, and nothing a desktop guest does not use.
/// A machine made from a template has no screen, because its windows reach the
/// host's desktop over vsock rather than through an emulated one, and no USB
/// controller, because nothing is plugged into it until its owner says so. On a
/// host with a GPU it has a GPU of its own, VirGL's, which renders its apps'
/// OpenGL on `render_node`. One that installs from CDs has a screen and a tablet to
/// show its installer with, and to show Windows' whole desktop once it is
/// installed.
fn domain_xml(
    spec: &MachineSpec,
    disk_volume: &str,
    render_node: Option<&str>,
) -> Result<String, String> {
    let (arch, board) = match spec.arch.as_str() {
        "x86_64" => ("x86_64", "q35"),
        "aarch64" => ("aarch64", "virt"),
        other => return Err(format!("libvirt machines on {other} are not supported")),
    };
    let (firmware, origin, title, installer) = match &spec.source {
        MachineSource::Template(template) => (
            template.firmware,
            format!(
                "<pm:template name='{}' digest='{}'/>",
                escape(&template.name),
                escape(&template.digest)
            ),
            format!("{}, from {}", label_name(spec.label), template.name),
            None,
        ),
        MachineSource::Installer(installer) => {
            let Some(first) = installer.media.first() else {
                return Err("a machine that installs from CDs needs at least one CD".into());
            };
            if installer.system == GuestSystem::Windows && arch != "x86_64" {
                return Err(format!("Windows machines on {arch} are not supported"));
            }
            let system = system_name(installer.system);
            let origin = std::iter::once(format!("<pm:system>{system}</pm:system>"))
                .chain(installer.media.iter().map(|media| {
                    format!(
                        "<pm:media name='{}' digest='{}'/>",
                        escape(&media.name),
                        escape(&media.digest)
                    )
                }))
                .collect::<Vec<_>>()
                .join("\n      ");
            (
                // Windows 11 will not install from a BIOS, and nothing else that
                // comes on a CD today needs one.
                Firmware::Uefi,
                origin,
                format!("{}, {system} from {}", label_name(spec.label), first.name),
                Some(installer),
            )
        }
    };
    let windows = installer.is_some_and(|installer| installer.system == GuestSystem::Windows);
    let firmware = match (firmware, arch) {
        // libvirt picks the firmware file itself, from the descriptors QEMU
        // installs, and keeps the machine's own copy of the variables. Secure
        // Boot is off: the template's boot loader is whatever its maker signed it
        // with, if anything, and the host's keys would refuse it. Windows 11's
        // Setup asks for Secure Boot too, and the answer file the host's drivers
        // CD carries tells it not to.
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
    let mut features = if arch == "x86_64" {
        "<acpi/>\n    <apic/>".to_owned()
    } else {
        "<acpi/>\n    <gic version='3'/>".to_owned()
    };
    // Windows runs far faster when it is told it is under a hypervisor and may use
    // the shortcuts Hyper-V gives it; KVM implements them, and TCG does not.
    if windows && spec.kvm {
        features.push_str(HYPERV);
    }
    let clock = if windows {
        // Windows keeps the hardware clock in local time, and Hyper-V's clock is
        // the one of its own it trusts under KVM.
        let hyperv = if spec.kvm {
            "\n    <timer name='hypervclock' present='yes'/>"
        } else {
            ""
        };
        format!(
            "<clock offset='localtime'>{hyperv}
    <timer name='rtc' tickpolicy='catchup'/>
    <timer name='pit' tickpolicy='delay'/>
    <timer name='hpet' present='no'/>
  </clock>"
        )
    } else {
        "<clock offset='utc'/>".to_owned()
    };
    // The disk boots first, so a machine whose system is installed starts it, and
    // an empty one falls through to its first CD: an installer that boots its own
    // menu again on every restart would otherwise never let the system it
    // installed start.
    let disk_boot = if installer.is_some() {
        "\n      <boot order='1'/>"
    } else {
        ""
    };
    let cds = installer
        .iter()
        .flat_map(|installer| installer.media.iter().enumerate())
        .map(|(index, media)| {
            let boot = if index == 0 {
                "\n      <boot order='2'/>"
            } else {
                ""
            };
            // SATA, which every installer has a driver for, Windows' included.
            format!(
                "
    <disk type='volume' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source pool='{POOL}' volume='{volume}'/>
      <target dev='sd{letter}' bus='sata'/>
      <readonly/>{boot}
    </disk>",
                volume = escape(&media_volume(media)),
                letter = char::from(b'a' + u8::try_from(index % 26).unwrap_or(0)),
            )
        })
        .collect::<String>();
    // Windows has nothing to listen on a vsock with; every other guest may run
    // the waypipe server that sends its windows to the desktop over one.
    let vsock = if windows {
        ""
    } else {
        "
    <!-- How the guest's windows reach the host's desktop. libvirt picks the
         address, and the host knows which machine an address is from libvirt
         alone, since the guest cannot choose its own. -->
    <vsock model='virtio'>
      <cid auto='yes'/>
    </vsock>"
    };
    let windows_devices = if windows {
        "
    <!-- Windows 11 will not install without a TPM 2.0; libvirt keeps its state
         beside the machine's and deletes it with the machine. -->
    <tpm model='tpm-crb'>
      <backend type='emulator' version='2.0'/>
    </tpm>"
    } else {
        ""
    };
    let (screen, usb) = if installer.is_some() {
        (
            "
    <!-- The screen, shown by a viewer that attaches through libvirt, and never
         on a port. No SPICE agent channel: the host's clipboard is not the
         guest's to read. -->
    <graphics type='spice'>
      <listen type='none'/>
    </graphics>
    <video>
      <model type='virtio' heads='1' primary='yes'/>
    </video>
    <!-- A USB tablet rather than a virtio one, which Windows Setup has no driver
         for: the pointer is where the host's is, with nothing to capture. -->
    <input type='tablet' bus='usb'/>"
                .to_owned(),
            "qemu-xhci",
        )
    } else if let Some(node) = render_node {
        (
            format!(
                "
    <!-- VirGL: the guest's OpenGL renders on the host's GPU, and its windows
         reach the desktop over vsock as GPU buffers. No screen to show, so
         egl-headless rather than SPICE, and no port. -->
    <graphics type='egl-headless'>
      <gl rendernode='{}'/>
    </graphics>
    <video>
      <model type='virtio' heads='1' primary='yes'>
        <acceleration accel3d='yes'/>
      </model>
    </video>",
                escape(node)
            ),
            "none",
        )
    } else {
        (String::new(), "none")
    };
    Ok(format!(
        "<domain type='{kind}'>
  <name>{name}</name>
  <title>{title}</title>
  <metadata>
    <pm:machine xmlns:pm='{LABEL_NAMESPACE}'>
      <pm:label>{label}</pm:label>
      {origin}
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
  {clock}
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <disk type='volume' device='disk'>
      <!-- discard='unmap' hands what the guest frees back to the pool. -->
      <driver name='qemu' type='qcow2' discard='unmap'/>
      <source pool='{POOL}' volume='{disk}'/>
      <target dev='{DISK_TARGET}' bus='virtio'/>{disk_boot}
    </disk>{cds}
    <interface type='network'>
      <source network='{NETWORK}'/>
      <model type='virtio'/>
    </interface>
    <!-- The QEMU guest agent: how the host starts a program in the guest. -->
    <channel type='unix'>
      <target type='virtio' name='org.qemu.guest_agent.0'/>
    </channel>{vsock}{windows_devices}{screen}
    <serial type='pty'>
      <target port='0'/>
    </serial>
    <console type='pty'/>
    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
    </rng>
    <memballoon model='virtio'/>
    <controller type='usb' model='{usb}'/>
  </devices>
</domain>
",
        name = escape(&spec.name),
        title = escape(&title),
        label = label_name(spec.label),
        memory = spec.memory_mib,
        cpus = spec.cpus,
        disk = escape(disk_volume),
    ))
}

/// The Hyper-V enlightenments a Windows guest is given under KVM: the set libvirt's
/// and virt-manager's own Windows defaults use.
const HYPERV: &str = "
    <hyperv mode='custom'>
      <relaxed state='on'/>
      <vapic state='on'/>
      <spinlocks state='on' retries='8191'/>
      <vpindex state='on'/>
      <runtime state='on'/>
      <synic state='on'/>
      <stimer state='on'/>
      <frequencies state='on'/>
      <tlbflush state='on'/>
      <ipi state='on'/>
    </hyperv>
    <vmport state='off'/>";

pub(crate) const fn system_name(system: GuestSystem) -> &'static str {
    match system {
        GuestSystem::Linux => "linux",
        GuestSystem::Windows => "windows",
    }
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
    use crate::pm::plugin::types::MachineInstaller;

    /// The steps on a host without a GPU.
    fn steps(request: MachineRequest) -> Result<Vec<MachineStep>, String> {
        super::steps(request, None)
    }

    fn spec(arch: &str, kvm: bool, firmware: Firmware) -> MachineSpec {
        MachineSpec {
            name: "work".into(),
            label: MachineLabel::Blue,
            source: MachineSource::Template(MachineTemplate {
                name: "losos-guest".into(),
                digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                image: "/usr/share/losos/machines/losos-guest.qcow2".into(),
                format: DiskFormat::Qcow2,
                file_size: 1 << 30,
                disk_size: 8 << 30,
                firmware,
            }),
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
    fn a_template_machine_gets_a_gpu_only_on_a_host_with_one() {
        let without = steps(MachineRequest::Create(spec("x86_64", true, Firmware::Uefi))).unwrap();
        let xml = &without[4].run.files[0].contents;
        for absent in ["<graphics", "<video>", "accel3d"] {
            assert!(!xml.contains(absent), "{absent} in\n{xml}");
        }

        let with = super::steps(
            MachineRequest::Create(spec("x86_64", true, Firmware::Uefi)),
            Some("/dev/dri/renderD128"),
        )
        .unwrap();
        let xml = &with[4].run.files[0].contents;
        for expected in [
            "<graphics type='egl-headless'>",
            "<gl rendernode='/dev/dri/renderD128'/>",
            "<acceleration accel3d='yes'/>",
        ] {
            assert!(xml.contains(expected), "{expected} in\n{xml}");
        }
        // Still no screen to show and nothing on a port.
        assert!(!xml.contains("spice"), "{xml}");
        for comment in xml.split("<!--").skip(1) {
            let body = comment.split("-->").next().unwrap();
            assert!(!body.contains("--"), "{body}");
        }
    }

    #[test]
    fn a_machine_from_a_cd_keeps_its_screen_with_a_gpu_on_the_host() {
        let steps = super::steps(
            MachineRequest::Create(installer(GuestSystem::Windows, true)),
            Some("/dev/dri/renderD128"),
        )
        .unwrap();
        let xml = &steps.last().unwrap().run.files[0].contents;
        assert!(xml.contains("<graphics type='spice'>"), "{xml}");
        assert!(!xml.contains("accel3d"), "{xml}");
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
            "-q undefine work --nvram --storage vda"
        );
        assert!(steps[1].when.is_none() && steps[1].undo.is_none());
    }

    fn installer(system: GuestSystem, kvm: bool) -> MachineSpec {
        let cd = |name: &str, digest: char| MachineMedia {
            name: name.into(),
            digest: digest.to_string().repeat(64),
            image: format!("/home/me/{name}.iso"),
            file_size: 5 << 30,
        };
        MachineSpec {
            name: "win".into(),
            label: MachineLabel::Red,
            source: MachineSource::Installer(MachineInstaller {
                system,
                media: vec![cd("win11", 'a'), cd("windows-tools", 'b')],
            }),
            disk_size: 64 << 30,
            memory_mib: 4096,
            cpus: 2,
            kvm,
            arch: "x86_64".into(),
        }
    }

    #[test]
    fn an_installer_machine_installs_each_cd_once_and_starts_empty() {
        let steps = steps(MachineRequest::Create(installer(
            GuestSystem::Windows,
            true,
        )))
        .unwrap();
        let runs: Vec<String> = steps.iter().map(|step| args(&step.run)).collect();
        let win11 = format!("pm-media-win11-{}.iso", "a".repeat(16));
        let tools = format!("pm-media-windows-tools-{}.iso", "b".repeat(16));
        assert_eq!(
            runs,
            [
                format!("-q vol-create-as default {win11} 5368709120B --format raw"),
                format!("-q vol-upload --pool default {win11} /home/me/win11.iso --sparse"),
                "-q pool-refresh default".into(),
                format!("-q vol-create-as default {tools} 5368709120B --format raw"),
                format!("-q vol-upload --pool default {tools} /home/me/windows-tools.iso --sparse"),
                "-q pool-refresh default".into(),
                "-q vol-create-as default pm-machine-win.qcow2 68719476736B --format qcow2".into(),
                "-q define domain.xml".into(),
            ]
        );
        for (step, volume) in steps[..3].iter().zip([&win11; 3]) {
            assert_eq!(
                args(step.unless.as_ref().unwrap()),
                format!("-q vol-info --pool default {volume}")
            );
        }
        assert_eq!(
            args(steps[6].undo.as_ref().unwrap()),
            "-q vol-delete --pool default pm-machine-win.qcow2"
        );
    }

    #[test]
    fn a_windows_machine_is_a_pc_windows_installs_on() {
        let steps = steps(MachineRequest::Create(installer(
            GuestSystem::Windows,
            true,
        )))
        .unwrap();
        let xml = &steps[7].run.files[0].contents;
        for expected in [
            "<title>red, windows from win11</title>",
            "<pm:system>windows</pm:system>",
            "<pm:media name='win11' digest='aaaa",
            "<pm:media name='windows-tools' digest='bbbb",
            "<os firmware='efi'>",
            "<feature enabled='no' name='secure-boot'/>",
            "<hyperv mode='custom'>",
            "<clock offset='localtime'>",
            "<timer name='hypervclock' present='yes'/>",
            "<tpm model='tpm-crb'>",
            "<backend type='emulator' version='2.0'/>",
            "<target dev='vda' bus='virtio'/>\n      <boot order='1'/>",
            "<target dev='sda' bus='sata'/>\n      <readonly/>\n      <boot order='2'/>",
            "<target dev='sdb' bus='sata'/>\n      <readonly/>\n    </disk>",
            "<graphics type='spice'>\n      <listen type='none'/>",
            "<input type='tablet' bus='usb'/>",
            "<controller type='usb' model='qemu-xhci'/>",
            "name='org.qemu.guest_agent.0'",
        ] {
            assert!(xml.contains(expected), "{expected} in\n{xml}");
        }
        // No vsock, nothing to share the host's clipboard with, and nothing on a
        // port.
        for absent in [
            "<vsock",
            "spicevmc",
            "vdagent",
            "autoport",
            "type='address'",
        ] {
            assert!(!xml.contains(absent), "{absent} in\n{xml}");
        }
        for comment in xml.split("<!--").skip(1) {
            let body = comment.split("-->").next().unwrap();
            assert!(!body.contains("--"), "{body}");
        }
    }

    #[test]
    fn hyper_v_needs_kvm_and_other_systems_keep_their_vsock() {
        let windows = steps(MachineRequest::Create(installer(
            GuestSystem::Windows,
            false,
        )))
        .unwrap();
        let xml = &windows[7].run.files[0].contents;
        assert!(!xml.contains("hyperv"), "{xml}");
        assert!(xml.contains("<clock offset='localtime'>"));

        let linux = steps(MachineRequest::Create(installer(GuestSystem::Linux, true))).unwrap();
        let xml = &linux[7].run.files[0].contents;
        assert!(xml.contains("<pm:system>linux</pm:system>"));
        assert!(xml.contains("<cid auto='yes'/>"));
        assert!(xml.contains("<clock offset='utc'/>"));
        assert!(xml.contains("<graphics type='spice'>"));
        for absent in ["hyperv", "<tpm"] {
            assert!(!xml.contains(absent), "{absent} in\n{xml}");
        }
    }

    #[test]
    fn an_installer_needs_a_cd_and_windows_a_pc() {
        let mut spec = installer(GuestSystem::Windows, true);
        spec.arch = "aarch64".into();
        assert!(steps_for(spec).is_err());
        let mut spec = installer(GuestSystem::Linux, true);
        let MachineSource::Installer(installer) = &mut spec.source else {
            unreachable!()
        };
        installer.media.clear();
        assert!(steps_for(spec).is_err());
    }
}

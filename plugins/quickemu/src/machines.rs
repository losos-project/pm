//! `pm machine`: a user's machines, as quickemu's.
//!
//! # Where things go
//!
//! Everything is under the directory pm names, `pm/machines` under the user's
//! `$XDG_DATA_HOME`:
//!
//! * `templates/<name>-<digest>.<format>` is a template, copied in read-only the
//!   first time a machine is made from it. It is a copy because the image pm was
//!   given may go away with the system that shipped it while machines still stand
//!   on it, and the image's digest is in the name, so a changed image is a new
//!   template beside the old one and the machines on the old one keep theirs.
//! * `cds/<name>-<digest>.iso` is a CD a machine installs its system from, copied
//!   in the same way and shared by every machine given the same bytes.
//! * `<name>.conf` is the machine as quickemu reads it: a shell file of settings
//!   ([`conf`]).
//! * `<name>/` is the machine's own folder: `disk.qcow2`, a copy-on-write layer
//!   over its template or, for a machine that installs from CDs, empty;
//!   `machine.json`, pm's record of it ([`record`]); and what quickemu keeps there
//!   itself: the UEFI variables, the TPM's state, the log and, while the machine
//!   runs, its pid file and the sockets of its monitor, its guest agent and its
//!   screen.
//!
//! So `templates` and `cds` cannot name a machine.
//!
//! # Running
//!
//! A machine runs as the service `pm-machine-<name>`, of the user's own service
//! manager (the system's, for root). `systemd-run` makes it around `quickemu --vm`
//! and it lasts as long as QEMU, whose pid file it follows; whether that service is
//! active is whether the machine runs. A desktop that starts a machine itself starts
//! the same service the same way, so pm and it agree on what runs.

use crate::{
    LAUNCHERS, MachinePlace, MachineRequest, MachineStep,
    pm::plugin::types::{
        DiskFormat, Firmware, GuestSystem, Launch, LaunchFile, MachineInstaller, MachineLabel,
        MachineMedia, MachineSource, MachineSpec, MachineTemplate,
    },
};

/// The host's bridge for machines: libvirt's old name for it, which LosOS's own
/// network keeps. A host without it gives a machine QEMU's own user networking.
const BRIDGE: &str = "virbr0";

/// The folders beside the machines' own, which no machine may be called.
const TEMPLATES: &str = "templates";
const CDS: &str = "cds";

/// The file each launch writes into its step's directory.
const CONF: &str = "machine.conf";
const RECORD: &str = "machine.json";

/// The steps that carry `request` out for the user `place` describes.
pub(crate) fn steps(
    request: MachineRequest,
    place: &MachinePlace,
) -> Result<Vec<MachineStep>, String> {
    let at = At::new(place)?;
    Ok(match request {
        MachineRequest::Create(spec) => create(&spec, &at)?,
        MachineRequest::List => vec![
            // Every folder of a machine, by its name.
            step(
                "list the machines",
                launch(
                    "find",
                    &[
                        &at.directory,
                        "-mindepth",
                        "1",
                        "-maxdepth",
                        "1",
                        "-type",
                        "d",
                        "!",
                        "-name",
                        TEMPLATES,
                        "!",
                        "-name",
                        CDS,
                        "-printf",
                        "%f\\n",
                    ],
                ),
            ),
            step(
                "list the ones that run",
                at.systemctl(&[
                    "list-units",
                    "--type=service",
                    "--plain",
                    "--no-legend",
                    "pm-machine-*",
                ]),
            ),
        ],
        MachineRequest::Start(name) => vec![MachineStep {
            unless: Some(at.running(&name)),
            ..step(&format!("start the machine {name}"), at.start(&name))
        }],
        // The power button: quickemu says `system_powerdown` on QEMU's monitor, and
        // the guest shuts down in its own time. Never without the `when`: quickemu
        // starts a machine that does not run before it says anything to it.
        MachineRequest::Stop(name) => vec![MachineStep {
            when: Some(at.running(&name)),
            ..step(
                &format!("ask the machine {name} to shut down"),
                launch(
                    "quickemu",
                    &["--vm", &at.conf(&name), "--monitor-cmd", "system_powerdown"],
                ),
            )
        }],
        MachineRequest::Kill(name) => vec![MachineStep {
            when: Some(at.running(&name)),
            ..step(&format!("power off the machine {name}"), at.stop(&name))
        }],
        MachineRequest::Remove(name) => vec![
            MachineStep {
                when: Some(at.running(&name)),
                ..step(&format!("power off the machine {name}"), at.stop(&name))
            },
            // The machine's folder and its settings, and nothing it was made from:
            // other machines may stand on the same template and CDs.
            step(
                &format!("delete the machine {name} and its disk"),
                launch("rm", &["-rf", "--", &at.folder(&name), &at.conf(&name)]),
            ),
        ],
    })
}

/// Where a user's machines are, and how their services are reached.
struct At {
    directory: String,
    user_manager: bool,
    random: Vec<u8>,
}

impl At {
    fn new(place: &MachinePlace) -> Result<Self, String> {
        let directory = place.directory.trim_end_matches('/').to_owned();
        // Every path below is handed to programs, some of them as `rm -rf`'s, and
        // pm promised an absolute one.
        if !directory.starts_with('/') || directory.split('/').any(|part| part == "..") {
            return Err(format!(
                "{} is not a directory to keep machines in",
                place.directory
            ));
        }
        if place.random.len() < 16 {
            return Err("pm gave too little randomness to make a machine with".into());
        }
        Ok(Self {
            directory,
            user_manager: place.user_manager,
            random: place.random.clone(),
        })
    }

    fn folder(&self, name: &str) -> String {
        format!("{}/{name}", self.directory)
    }

    fn conf(&self, name: &str) -> String {
        format!("{}/{name}.conf", self.directory)
    }

    fn shared(&self, kind: &str, file: &str) -> String {
        format!("{}/{kind}/{file}", self.directory)
    }

    /// `systemctl`, at the manager the machines run under.
    fn systemctl(&self, args: &[&str]) -> Launch {
        let mut all = Vec::with_capacity(args.len() + 1);
        if self.user_manager {
            all.push("--user");
        }
        all.extend_from_slice(args);
        launch("systemctl", &all)
    }

    /// A probe that succeeds while `name` runs.
    fn running(&self, name: &str) -> Launch {
        self.systemctl(&["--quiet", "is-active", &unit(name)])
    }

    /// The machine's service, made and started.
    ///
    /// quickemu starts QEMU in the background and leaves, so the service is a
    /// forking one that follows QEMU's pid file. `--collect` forgets it once it
    /// stops, however it stopped: a failed one would otherwise keep the name, and
    /// the next start would find it taken.
    fn start(&self, name: &str) -> Launch {
        let pid = format!("PIDFile={}/{name}.pid", self.folder(name));
        let description = format!("--description=The machine {name}");
        let unit = format!("--unit={}", unit(name));
        let conf = self.conf(name);
        let mut args = Vec::new();
        if self.user_manager {
            args.push("--user");
        }
        args.extend_from_slice(&[
            unit.as_str(),
            description.as_str(),
            "--collect",
            "--quiet",
            "--property=Type=forking",
            "--property",
            &pid,
            "quickemu",
            "--vm",
            &conf,
        ]);
        launch("systemd-run", &args)
    }

    /// The machine's service, stopped: QEMU and the TPM beside it end at once.
    fn stop(&self, name: &str) -> Launch {
        self.systemctl(&["stop", &unit(name)])
    }

    /// `count` of the random bytes from `from` on, as one number.
    fn number(&self, from: usize, count: usize) -> u64 {
        self.random[from..from + count]
            .iter()
            .fold(0, |number, byte| number << 8 | u64::from(*byte))
    }
}

/// The service a machine runs as.
pub(crate) fn unit(name: &str) -> String {
    format!("pm-machine-{name}.service")
}

/// Check the machine is new, install the template or CDs that are not installed,
/// and make the machine: its folder, its disk, its settings and pm's record of it.
fn create(spec: &MachineSpec, at: &At) -> Result<Vec<MachineStep>, String> {
    let name = &spec.name;
    if [TEMPLATES, CDS].contains(&name.as_str()) {
        return Err(format!(
            "`{name}` is where machines' {name} are kept, so no machine can be called that"
        ));
    }
    let arch = match spec.arch.as_str() {
        arch @ ("x86_64" | "aarch64") => arch,
        other => return Err(format!("quickemu machines on {other} are not supported")),
    };
    let folder = at.folder(name);
    let disk = format!("{folder}/disk.qcow2");
    let conf = at.conf(name);

    let mut steps = vec![step(
        &format!("check there is no machine called {name} yet"),
        launch("test", &["!", "-e", &folder, "-a", "!", "-e", &conf]),
    )];
    let make_disk = match &spec.source {
        MachineSource::Template(template) => {
            let installed = at.shared(TEMPLATES, &template_file(template));
            steps.extend(install(
                &format!("the template {}", template.name),
                &template.image,
                &at.shared(TEMPLATES, ""),
                &installed,
            ));
            launch(
                "qemu-img",
                &[
                    "create",
                    "-q",
                    "-f",
                    "qcow2",
                    "-F",
                    format_name(template.format),
                    "-b",
                    &installed,
                    &disk,
                    &spec.disk_size.to_string(),
                ],
            )
        }
        MachineSource::Installer(installer) => {
            for media in &installer.media {
                steps.extend(install(
                    &format!("the CD {}", media.name),
                    &media.image,
                    &at.shared(CDS, ""),
                    &at.shared(CDS, &media_file(media)),
                ));
            }
            launch(
                "qemu-img",
                &[
                    "create",
                    "-q",
                    "-f",
                    "qcow2",
                    &disk,
                    &spec.disk_size.to_string(),
                ],
            )
        }
    };
    let cid = vsock_address(spec, at);
    let conf_text = self::conf(spec, at, arch, &disk, cid)?;
    steps.extend([
        // Made, not `-p`: the check above looked, but only this is sure no folder
        // was there to take back.
        MachineStep {
            undo: Some(launch("rm", &["-rf", "--", &folder])),
            ..step(
                &format!("make the folder of the machine {name}"),
                launch("mkdir", &["-m", "0700", &folder]),
            )
        },
        step(&format!("make the disk of the machine {name}"), make_disk),
        MachineStep {
            undo: Some(launch("rm", &["-f", "--", &conf])),
            ..step(
                &format!("write the settings of the machine {name}"),
                with_file(launch("cp", &[CONF, &conf]), CONF, conf_text),
            )
        },
        // Last: a desktop takes a folder with a record in it for a whole machine.
        step(
            &format!("record the machine {name}"),
            with_file(
                launch("cp", &[RECORD, &format!("{folder}/{RECORD}")]),
                RECORD,
                record(spec, at, cid),
            ),
        ),
    ]);
    Ok(steps)
}

/// The steps that copy `image` into `folder` as `installed`, read-only, each
/// skipped when it is there already.
///
/// Through a `.part` beside it, renamed only once the copy is whole: a copy cut
/// short would otherwise be taken for the template by every later machine.
fn install(what: &str, image: &str, folder: &str, installed: &str) -> [MachineStep; 4] {
    let there = launch("test", &["-e", installed]);
    let part = format!("{installed}.part");
    [
        // Always: a folder that is there already is no failure.
        step(
            &format!("make {}", folder.trim_end_matches('/')),
            launch("mkdir", &["-p", "-m", "0700", folder]),
        ),
        MachineStep {
            unless: Some(there.clone()),
            undo: Some(launch("rm", &["-f", "--", &part])),
            // Holes in a raw image stay holes in the copy.
            ..step(
                &format!("copy {image} in as {what}"),
                launch("cp", &["--sparse=always", "--", image, &part]),
            )
        },
        // Every machine made from it writes only on its own layer above it.
        MachineStep {
            unless: Some(there.clone()),
            ..step(
                &format!("make {what} read-only"),
                launch("chmod", &["0444", &part]),
            )
        },
        MachineStep {
            unless: Some(there),
            undo: Some(launch("rm", &["-f", "--", installed])),
            ..step(
                &format!("install {what}"),
                launch("mv", &["--", &part, installed]),
            )
        },
    ]
}

/// The template's file: its name, then enough of its digest that two images of one
/// name never share a file.
fn template_file(template: &MachineTemplate) -> String {
    let digest: String = template.digest.chars().take(16).collect();
    format!(
        "{}-{digest}.{}",
        template.name,
        format_name(template.format)
    )
}

/// A CD's file, named as a template's is.
fn media_file(media: &MachineMedia) -> String {
    let digest: String = media.digest.chars().take(16).collect();
    format!("{}-{digest}.iso", media.name)
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

const fn system_name(system: GuestSystem) -> &'static str {
    match system {
        GuestSystem::Linux => "linux",
        GuestSystem::Windows => "windows",
    }
}

fn is_windows(spec: &MachineSpec) -> bool {
    matches!(
        &spec.source,
        MachineSource::Installer(MachineInstaller {
            system: GuestSystem::Windows,
            ..
        })
    )
}

/// The machine's vsock address, which its windows reach the host's desktop from,
/// or none for Windows, which has nothing to listen on one with.
///
/// Drawn at random, since the plugin cannot see which addresses other machines
/// have, from the 2³² - 4 a guest can have (0, 1 and 2 are the hypervisor's, the
/// loopback's and the host's, and the last means "any"). Two machines that drew the
/// same one would find out when the second started, as QEMU refuses an address in
/// use, and among a person's few machines that is about one chance in a billion.
fn vsock_address(spec: &MachineSpec, at: &At) -> Option<u32> {
    if is_windows(spec) {
        return None;
    }
    let drawn = at.number(0, 4);
    u32::try_from(3 + drawn % (u64::from(u32::MAX) - 3)).ok()
}

/// The machine's settings, as quickemu reads them: shell variables, which quickemu
/// sources.
///
/// What quickemu would otherwise decide for a desktop of its own is decided here:
/// its screen is SPICE on a socket in the machine's folder, never on a port, and
/// quickemu starts no viewer, since the desktop shows the screen when its owner
/// asks; no folder of the host is shared into it. A Linux machine draws on the
/// host's GPU through VirGL whenever the host has one at its start, and in
/// software when it has none; Windows has no VirGL driver, so it never does.
fn conf(
    spec: &MachineSpec,
    at: &At,
    arch: &str,
    disk: &str,
    cid: Option<u32>,
) -> Result<String, String> {
    let windows = is_windows(spec);
    if windows && arch != "x86_64" {
        return Err(format!("Windows machines on {arch} are not supported"));
    }
    let (firmware, origin) = match &spec.source {
        MachineSource::Template(template) => (template.firmware, None),
        MachineSource::Installer(installer) => {
            if installer.media.is_empty() {
                return Err("a machine that installs from CDs needs at least one CD".into());
            }
            if installer.media.len() > 2 {
                return Err(
                    "quickemu gives a machine two CDs at most: the installer's and one of tools"
                        .into(),
                );
            }
            // Windows 11 will not install from a BIOS, and nothing else that comes
            // on a CD today needs one.
            (Firmware::Uefi, Some(installer))
        }
    };
    let boot = match (firmware, arch) {
        (Firmware::Uefi, _) => "efi",
        (Firmware::Bios, "x86_64") => "legacy",
        (Firmware::Bios, _) => return Err(format!("an {arch} machine cannot boot from a BIOS")),
    };
    let mut lines = vec![
        "# A machine pm made (`pm machine create`). quickemu reads this, and".to_owned(),
        "# pm's own record of the machine is machine.json in its folder.".to_owned(),
        format!(
            "guest_os={}",
            quote(if windows { "windows" } else { "linux" })
        ),
        format!("arch={}", quote(arch)),
        format!("disk_img={}", quote(disk)),
        format!("ram={}", quote(&format!("{}M", spec.memory_mib))),
        format!("cpu_cores={}", quote(&spec.cpus.to_string())),
        format!("boot={}", quote(boot)),
        // The template's boot loader is whatever its maker signed it with, if
        // anything. Windows 11's Setup asks for Secure Boot too, and the answer
        // file on the host's drivers CD tells it not to.
        "secureboot='off'".into(),
        // Windows 11 will not install without a TPM 2.0. quickemu starts swtpm
        // for it, keeping its state in the machine's folder.
        format!("tpm={}", quote(if windows { "on" } else { "off" })),
        "display='spice'".into(),
        "viewer='none'".into(),
        "public_dir='none'".into(),
        "gl='off'".into(),
    ];
    if !windows {
        lines.extend([
            // VirGL: the machine's apps draw on the host's GPU, on the first
            // render node its owner can open, read when the machine starts so a
            // GPU added or taken away since it was made counts. quickemu would
            // otherwise ask for GL on a host with no GPU and fail to start it.
            // `rendernode` is the losos-desktop quickemu's, which upstream
            // fixes at renderD128.
            "for node in /dev/dri/renderD*; do".into(),
            "  [ -r \"$node\" ] && [ -w \"$node\" ] && { gl='on'; rendernode=\"$node\"; break; }"
                .into(),
            "done".into(),
        ]);
    }
    lines.extend([
        format!("macaddr={}", quote(&mac_address(at))),
        format!("network={}", quote(BRIDGE)),
        format!("[ -d /sys/class/net/{BRIDGE} ] || network=''"),
    ]);
    match origin {
        None => lines.extend([
            // Its sound reaches the host with its windows, not through a card.
            "sound_card='none'".into(),
            // quickemu boots a disk it thinks unused from a CD, and refuses one
            // with no CD, and a template's new layer is small enough to look
            // unused. The setting only changes a disk quickemu makes itself, and
            // pm made this one, so all it does here is skip that look.
            "preallocation='metadata'".into(),
        ]),
        Some(installer) => {
            // The first CD is booted while the disk has nothing on it, and the
            // second stays in its drive.
            let mut cds = installer
                .media
                .iter()
                .map(|media| at.shared(CDS, &media_file(media)));
            if let Some(first) = cds.next() {
                lines.push(format!("iso={}", quote(&first)));
            }
            if let Some(second) = cds.next() {
                lines.push(format!("fixed_iso={}", quote(&second)));
            }
        }
    }
    if let Some(cid) = cid {
        lines.push(format!(
            "extra_args={}",
            quote(&format!("-device vhost-vsock-pci,guest-cid={cid}"))
        ));
    }
    let mut text = lines.join("\n");
    text.push('\n');
    Ok(text)
}

/// `text` as a single-quoted shell word.
fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// A network card's address of its own: QEMU's prefix, which marks it locally
/// administered, and three random bytes.
fn mac_address(at: &At) -> String {
    let bytes = at.number(4, 3).to_be_bytes();
    format!(
        "52:54:00:{:02x}:{:02x}:{:02x}",
        bytes[5], bytes[6], bytes[7]
    )
}

/// A random UUID (version 4), which names the machine for its life whatever it is
/// renamed to.
fn uuid(at: &At) -> String {
    let mut bytes: Vec<u8> = at.random[..16].to_vec();
    bytes[6] = bytes[6] & 0x0f | 0x40;
    bytes[8] = bytes[8] & 0x3f | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// `machine.json`: what the machine is, for a desktop to show it by.
///
/// derisk reads it (losos-project/derisk, `crates/derisk-machines/src/machine.rs`):
/// a change here is a change there. Every field is always present:
///
/// * `name`, `uuid`;
/// * `label`, the colour its windows are framed in;
/// * `template`, `{ name, digest }` of what it was made from, or null;
/// * `system`, what it installs from CDs (`linux` or `windows`), or null, and
///   `media`, those CDs, `[{ name, digest }]`;
/// * `screen`, whether it is seen through its screen rather than as windows on the
///   desktop, as one installing from CDs is;
/// * `memory_mib`, `cpus`;
/// * `cid`, its vsock address, or null.
fn record(spec: &MachineSpec, at: &At, cid: Option<u32>) -> String {
    let (template, system, media) = match &spec.source {
        MachineSource::Template(template) => (
            format!(
                "{{\"name\": {}, \"digest\": {}}}",
                json(&template.name),
                json(&template.digest)
            ),
            "null".to_owned(),
            Vec::new(),
        ),
        MachineSource::Installer(installer) => (
            "null".to_owned(),
            json(system_name(installer.system)),
            installer
                .media
                .iter()
                .map(|media| {
                    format!(
                        "{{\"name\": {}, \"digest\": {}}}",
                        json(&media.name),
                        json(&media.digest)
                    )
                })
                .collect(),
        ),
    };
    format!(
        "{{\n  \"name\": {name},\n  \"uuid\": {uuid},\n  \"label\": {label},\n  \"template\": {template},\n  \
         \"system\": {system},\n  \"media\": [{media}],\n  \"screen\": {screen},\n  \"memory_mib\": {memory},\n  \
         \"cpus\": {cpus},\n  \"cid\": {cid}\n}}\n",
        name = json(&spec.name),
        uuid = json(&uuid(at)),
        label = json(label_name(spec.label)),
        media = media.join(", "),
        screen = matches!(spec.source, MachineSource::Installer(_)),
        memory = spec.memory_mib,
        cpus = spec.cpus,
        cid = cid.map_or_else(|| "null".to_owned(), |cid| cid.to_string()),
    )
}

/// `text` as a JSON string.
fn json(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
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

fn launch(program: &str, args: &[&str]) -> Launch {
    debug_assert!(LAUNCHERS.contains(&program), "{program} is not a launcher");
    Launch {
        program: program.into(),
        args: args.iter().map(|&arg| arg.into()).collect(),
        files: Vec::new(),
    }
}

fn with_file(launch: Launch, name: &str, contents: String) -> Launch {
    Launch {
        files: vec![LaunchFile {
            name: name.into(),
            contents,
        }],
        ..launch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn place(user_manager: bool) -> MachinePlace {
        MachinePlace {
            directory: "/home/me/.local/share/pm/machines".into(),
            user_manager,
            random: (0..32).collect(),
            render_node: None,
        }
    }

    fn spec(arch: &str, firmware: Firmware) -> MachineSpec {
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
            kvm: true,
            arch: arch.into(),
        }
    }

    fn line(launch: &Launch) -> String {
        std::iter::once(launch.program.as_str())
            .chain(launch.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }

    const DIR: &str = "/home/me/.local/share/pm/machines";

    #[test]
    fn create_installs_the_template_once_then_makes_the_machine() {
        let steps = steps(
            MachineRequest::Create(spec("x86_64", Firmware::Uefi)),
            &place(true),
        )
        .unwrap();
        let runs: Vec<String> = steps.iter().map(|step| line(&step.run)).collect();
        let template = format!("{DIR}/templates/losos-guest-0123456789abcdef.qcow2");
        assert_eq!(
            runs,
            [
                format!("test ! -e {DIR}/work -a ! -e {DIR}/work.conf"),
                format!("mkdir -p -m 0700 {DIR}/templates/"),
                format!(
                    "cp --sparse=always -- /usr/share/losos/machines/losos-guest.qcow2 {template}.part"
                ),
                format!("chmod 0444 {template}.part"),
                format!("mv -- {template}.part {template}"),
                format!("mkdir -m 0700 {DIR}/work"),
                format!(
                    "qemu-img create -q -f qcow2 -F qcow2 -b {template} {DIR}/work/disk.qcow2 34359738368"
                ),
                format!("cp machine.conf {DIR}/work.conf"),
                format!("cp machine.json {DIR}/work/machine.json"),
            ]
        );
        // The template's copy is skipped together when it is there already.
        for step in &steps[2..5] {
            assert_eq!(
                line(step.unless.as_ref().unwrap()),
                format!("test -e {template}")
            );
        }
        assert!(steps[1].unless.is_none(), "mkdir -p is always safe");
        // And what the request made is taken back if a later step fails.
        assert_eq!(
            line(steps[2].undo.as_ref().unwrap()),
            format!("rm -f -- {template}.part")
        );
        assert_eq!(
            line(steps[4].undo.as_ref().unwrap()),
            format!("rm -f -- {template}")
        );
        assert_eq!(
            line(steps[5].undo.as_ref().unwrap()),
            format!("rm -rf -- {DIR}/work")
        );
        assert_eq!(
            line(steps[7].undo.as_ref().unwrap()),
            format!("rm -f -- {DIR}/work.conf")
        );
        assert!(steps[0].undo.is_none() && steps[0].unless.is_none());
    }

    fn file(step: &MachineStep) -> &str {
        let [file] = step.run.files.as_slice() else {
            panic!("one file");
        };
        &file.contents
    }

    #[test]
    fn the_settings_put_the_machine_on_the_bridge_with_a_vsock_and_a_private_screen() {
        let steps = steps(
            MachineRequest::Create(spec("x86_64", Firmware::Uefi)),
            &place(true),
        )
        .unwrap();
        let conf = file(&steps[7]);
        for expected in [
            "guest_os='linux'",
            "arch='x86_64'",
            &format!("disk_img='{DIR}/work/disk.qcow2'"),
            "ram='2048M'",
            "cpu_cores='2'",
            "boot='efi'",
            "secureboot='off'",
            "tpm='off'",
            "display='spice'",
            "viewer='none'",
            "public_dir='none'",
            "gl='off'",
            "for node in /dev/dri/renderD*; do",
            "{ gl='on'; rendernode=\"$node\"; break; }",
            "network='virbr0'",
            "[ -d /sys/class/net/virbr0 ] || network=''",
            "sound_card='none'",
            "preallocation='metadata'",
            "macaddr='52:54:00:04:05:06'",
            "extra_args='-device vhost-vsock-pci,guest-cid=66054'",
        ] {
            assert!(conf.contains(expected), "{expected} in\n{conf}");
        }
        assert!(!conf.contains("iso="), "{conf}");
    }

    #[test]
    fn the_record_says_what_a_desktop_shows() {
        let steps = steps(
            MachineRequest::Create(spec("x86_64", Firmware::Uefi)),
            &place(true),
        )
        .unwrap();
        let record = file(&steps[8]);
        for expected in [
            "\"name\": \"work\"",
            "\"uuid\": \"00010203-0405-4607-8809-0a0b0c0d0e0f\"",
            "\"label\": \"blue\"",
            "\"template\": {\"name\": \"losos-guest\", \"digest\": \"0123456789abcdef",
            "\"system\": null",
            "\"media\": []",
            "\"screen\": false",
            "\"memory_mib\": 2048",
            "\"cpus\": 2",
            "\"cid\": 66054",
        ] {
            assert!(record.contains(expected), "{expected} in\n{record}");
        }
    }

    #[test]
    fn a_bios_template_boots_legacy_but_only_on_a_pc() {
        let steps = steps(
            MachineRequest::Create(spec("x86_64", Firmware::Bios)),
            &place(true),
        )
        .unwrap();
        assert!(file(&steps[7]).contains("boot='legacy'"));
        let aarch64 = steps_for(spec("aarch64", Firmware::Uefi)).unwrap();
        assert!(file(&aarch64[7]).contains("arch='aarch64'"));
        assert!(steps_for(spec("aarch64", Firmware::Bios)).is_err());
        assert!(steps_for(spec("riscv64", Firmware::Uefi)).is_err());
    }

    fn steps_for(spec: MachineSpec) -> Result<Vec<MachineStep>, String> {
        steps(MachineRequest::Create(spec), &place(true))
    }

    #[test]
    fn names_of_the_shared_folders_and_odd_places_are_refused() {
        for name in ["templates", "cds"] {
            let mut spec = spec("x86_64", Firmware::Uefi);
            spec.name = name.into();
            assert!(steps_for(spec).is_err(), "{name}");
        }
        for directory in ["relative/machines", "/home/me/../other"] {
            let place = MachinePlace {
                directory: directory.into(),
                ..place(true)
            };
            assert!(steps(MachineRequest::List, &place).is_err(), "{directory}");
        }
    }

    #[test]
    fn lifecycle_requests_ask_the_users_service_manager_whether_the_machine_runs() {
        let one = |request, user| {
            let mut steps = steps(request, &place(user)).unwrap();
            assert_eq!(steps.len(), 1);
            steps.remove(0)
        };
        let start = one(MachineRequest::Start("work".into()), true);
        assert_eq!(
            line(&start.run),
            format!(
                "systemd-run --user --unit=pm-machine-work.service --description=The machine work \
                 --collect --quiet --property=Type=forking --property PIDFile={DIR}/work/work.pid \
                 quickemu --vm {DIR}/work.conf"
            )
        );
        let running = "systemctl --user --quiet is-active pm-machine-work.service";
        assert_eq!(line(start.unless.as_ref().unwrap()), running);

        let stop = one(MachineRequest::Stop("work".into()), true);
        assert_eq!(
            line(&stop.run),
            format!("quickemu --vm {DIR}/work.conf --monitor-cmd system_powerdown")
        );
        assert_eq!(line(stop.when.as_ref().unwrap()), running);

        let kill = one(MachineRequest::Kill("work".into()), true);
        assert_eq!(
            line(&kill.run),
            "systemctl --user stop pm-machine-work.service"
        );
        assert_eq!(line(kill.when.as_ref().unwrap()), running);

        // Root's machines are the system's.
        let start = one(MachineRequest::Start("work".into()), false);
        assert!(line(&start.run).starts_with("systemd-run --unit=pm-machine-work.service"));
        assert_eq!(
            line(start.unless.as_ref().unwrap()),
            "systemctl --quiet is-active pm-machine-work.service"
        );
    }

    #[test]
    fn remove_powers_off_then_deletes_the_machine_but_not_the_template() {
        let steps = steps(MachineRequest::Remove("work".into()), &place(true)).unwrap();
        assert_eq!(
            line(&steps[0].run),
            "systemctl --user stop pm-machine-work.service"
        );
        assert!(steps[0].when.is_some());
        assert_eq!(
            line(&steps[1].run),
            format!("rm -rf -- {DIR}/work {DIR}/work.conf")
        );
        assert!(steps[1].when.is_none() && steps[1].undo.is_none());
    }

    #[test]
    fn list_names_the_machines_and_the_ones_that_run() {
        let steps = steps(MachineRequest::List, &place(true)).unwrap();
        assert_eq!(
            line(&steps[0].run),
            format!(
                "find {DIR} -mindepth 1 -maxdepth 1 -type d ! -name templates ! -name cds -printf %f\\n"
            )
        );
        assert_eq!(
            line(&steps[1].run),
            "systemctl --user list-units --type=service --plain --no-legend pm-machine-*"
        );
    }

    fn installer(system: GuestSystem) -> MachineSpec {
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
            kvm: true,
            arch: "x86_64".into(),
        }
    }

    #[test]
    fn an_installer_machine_copies_each_cd_once_and_starts_empty() {
        let steps = steps_for(installer(GuestSystem::Windows)).unwrap();
        let runs: Vec<String> = steps.iter().map(|step| line(&step.run)).collect();
        let win11 = format!("{DIR}/cds/win11-{}.iso", "a".repeat(16));
        let tools = format!("{DIR}/cds/windows-tools-{}.iso", "b".repeat(16));
        assert_eq!(
            runs[2],
            format!("cp --sparse=always -- /home/me/win11.iso {win11}.part")
        );
        assert_eq!(
            runs[6],
            format!("cp --sparse=always -- /home/me/windows-tools.iso {tools}.part")
        );
        assert_eq!(
            runs[10],
            format!("qemu-img create -q -f qcow2 {DIR}/win/disk.qcow2 68719476736")
        );
        let conf = file(&steps[11]);
        for expected in [
            "guest_os='windows'",
            "tpm='on'",
            "boot='efi'",
            "secureboot='off'",
            &format!("iso='{win11}'"),
            &format!("fixed_iso='{tools}'"),
        ] {
            assert!(conf.contains(expected), "{expected} in\n{conf}");
        }
        // No vsock, which Windows has no use for, a disk quickemu looks at to
        // know whether to boot the CD, and no VirGL, which Windows has no
        // driver for.
        assert!(conf.contains("gl='off'"), "{conf}");
        for absent in ["vhost-vsock", "preallocation", "sound_card", "gl='on'"] {
            assert!(!conf.contains(absent), "{absent} in\n{conf}");
        }
        let record = file(&steps[12]);
        for expected in [
            "\"system\": \"windows\"",
            "\"template\": null",
            "\"media\": [{\"name\": \"win11\", \"digest\": \"aaaa",
            "\"screen\": true",
            "\"cid\": null",
            "\"label\": \"red\"",
        ] {
            assert!(record.contains(expected), "{expected} in\n{record}");
        }
    }

    #[test]
    fn a_linux_installer_keeps_its_vsock() {
        let steps = steps_for(installer(GuestSystem::Linux)).unwrap();
        let conf = file(&steps[11]);
        assert!(conf.contains("guest_os='linux'"));
        assert!(conf.contains("tpm='off'"));
        assert!(conf.contains("vhost-vsock-pci"));
        assert!(conf.contains("{ gl='on'; rendernode=\"$node\"; break; }"));
    }

    #[test]
    fn an_installer_needs_one_or_two_cds_and_windows_a_pc() {
        let mut spec = installer(GuestSystem::Windows);
        spec.arch = "aarch64".into();
        assert!(steps_for(spec).is_err());
        let mut spec = installer(GuestSystem::Linux);
        let MachineSource::Installer(installer) = &mut spec.source else {
            unreachable!()
        };
        let third = installer.media[0].clone();
        installer.media.push(third);
        assert!(steps_for(spec.clone()).is_err());
        let MachineSource::Installer(installer) = &mut spec.source else {
            unreachable!()
        };
        installer.media.clear();
        assert!(steps_for(spec).is_err());
    }

    #[test]
    fn settings_are_quoted_for_the_shell_that_reads_them() {
        assert_eq!(quote("it's"), r"'it'\''s'");
        assert_eq!(json("a\"b\\c\n"), r#""a\"b\\c\u000a""#);
    }
}

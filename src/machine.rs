//! The host's persistent virtual machines, for `pm machine`.
//!
//! A package that ships its own kernel boots in a machine that lives exactly as long
//! as `pm run` (see [`crate::vm`]). These are the other kind: machines that stay
//! defined until they are removed, each made from a *template* - a disk image - with
//! a copy-on-write disk of its own on top, started and stopped as their owner likes.
//! On LosOS they are where a person's work runs, one machine per kind of work, each
//! window framed in its machine's [`Label`].
//!
//! pm knows what a machine is and what can be asked of it, but not how a hypervisor
//! does any of it. A [`Manager`] - on a real host, a plugin built against the
//! `machine-plugin` world, such as `libvirt` - turns each [`Request`] into the
//! [`Step`]s that carry it out, and [`carry_out`] runs them: the plugin decides, pm
//! executes, and everything it can execute is one of the programs the plugin listed
//! when it loaded.

use std::{
    fmt,
    fs::{self, DirBuilder, File},
    io::{self, Read},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr,
};

use miette::{IntoDiagnostic, WrapErr, miette};
use ring::digest::{Context, SHA256};
use tracing::{debug, info, warn};

use crate::vm::{Launch, find_on_path, launch::write_file};

/// The colour a machine's windows are framed in. Qubes OS's eight, in its order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Label {
    /// For what must not leak.
    Red,
    /// Between red and yellow.
    Orange,
    /// Between orange and green.
    Yellow,
    /// For what is trusted.
    Green,
    /// The default: no claim either way.
    #[default]
    Gray,
    /// For work.
    Blue,
    /// Between blue and black.
    Purple,
    /// For what is most trusted.
    Black,
}

impl Label {
    /// Every label, in Qubes OS's order.
    pub const ALL: [Self; 8] = [
        Self::Red,
        Self::Orange,
        Self::Yellow,
        Self::Green,
        Self::Gray,
        Self::Blue,
        Self::Purple,
        Self::Black,
    ];

    /// The label's name, as `--label` takes it and as a machine's definition
    /// records it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Red => "red",
            Self::Orange => "orange",
            Self::Yellow => "yellow",
            Self::Green => "green",
            Self::Gray => "gray",
            Self::Blue => "blue",
            Self::Purple => "purple",
            Self::Black => "black",
        }
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Label {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|label| label.name() == name)
            .ok_or_else(|| {
                format!(
                    "`{name}` is not a label; one of {}",
                    Self::ALL.map(Self::name).join(", ")
                )
            })
    }
}

/// How a disk image is laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskFormat {
    /// The disk's bytes, one for one.
    Raw,
    /// QEMU's copy-on-write format.
    Qcow2,
}

impl DiskFormat {
    /// The format's name, as QEMU and libvirt spell it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Qcow2 => "qcow2",
        }
    }
}

/// What a machine's firmware is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Firmware {
    /// UEFI without Secure Boot. Every image LosOS makes boots this way, and arm64
    /// has nothing else.
    #[default]
    Uefi,
    /// A legacy PC BIOS. x86-64 only.
    Bios,
}

impl FromStr for Firmware {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "uefi" => Ok(Self::Uefi),
            "bios" => Ok(Self::Bios),
            _ => Err(format!("`{name}` is not a firmware; uefi or bios")),
        }
    }
}

/// The image a machine is made from, already on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    /// What it is called: 1-64 characters of `[a-z0-9]`, `.`, `_` and `-`.
    pub name: String,
    /// The image's SHA-256, in lowercase hex.
    pub digest: String,
    /// The image file.
    pub image: PathBuf,
    /// How the image is laid out.
    pub format: DiskFormat,
    /// The image file's length in bytes.
    pub file_size: u64,
    /// The size of the disk the image describes, in bytes.
    pub disk_size: u64,
    /// The firmware it boots with.
    pub firmware: Firmware,
}

/// The first four bytes of every qcow2 image.
const QCOW2_MAGIC: [u8; 4] = *b"QFI\xfb";

/// Where a qcow2 header keeps the disk's size: a big-endian `u64` at byte 24, in
/// every version of the format.
const QCOW2_SIZE_OFFSET: usize = 24;

impl Template {
    /// The template `image` is, named `name` or, without one, after the file.
    ///
    /// Reads the whole image once, for its digest: a template is the base every
    /// machine made from it writes on top of, so pm has to know that the image it
    /// installs under a name is the one it installed under that name before.
    ///
    /// # Errors
    ///
    /// The image cannot be read, its header is cut short, or no usable name comes
    /// out of `name` or the file's name.
    pub fn from_image(
        image: &Path,
        name: Option<&str>,
        firmware: Firmware,
    ) -> miette::Result<Self> {
        let image = image
            .canonicalize()
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot find the image {}", image.display()))?;
        let mut file = File::open(&image)
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot open the image {}", image.display()))?;
        let file_size = file.metadata().into_diagnostic()?.len();

        let mut header = [0u8; QCOW2_SIZE_OFFSET + 8];
        let read = read_up_to(&mut file, &mut header)
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot read the image {}", image.display()))?;
        let (format, disk_size) = if header[..read].starts_with(&QCOW2_MAGIC) {
            if read < header.len() {
                return Err(miette!(
                    "{} starts like a qcow2 image but its header is cut short",
                    image.display()
                ));
            }
            let mut size = [0u8; 8];
            size.copy_from_slice(&header[QCOW2_SIZE_OFFSET..]);
            (DiskFormat::Qcow2, u64::from_be_bytes(size))
        } else {
            (DiskFormat::Raw, file_size)
        };

        let digest = digest_of(&mut file, &header[..read])
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot read the image {}", image.display()))?;

        let name = match name {
            Some(name) => name.to_owned(),
            None => name_of_image(&image),
        };
        check_template_name(&name)?;
        debug!(%name, format = format.name(), disk_size, "read the template image");
        Ok(Self {
            name,
            digest,
            image,
            format,
            file_size,
            disk_size,
            firmware,
        })
    }
}

/// The SHA-256 of `start` followed by the rest of `file`, in lowercase hex.
fn digest_of(file: &mut File, start: &[u8]) -> io::Result<String> {
    let mut context = Context::new(&SHA256);
    context.update(start);
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        context.update(&buffer[..n]);
    }
    Ok(context
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// What runs in a machine that installs its own system from CDs. It decides the
/// devices the machine gets: a guest that cannot send its windows to the host's
/// desktop over vsock, as Windows cannot, gets a screen instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum System {
    /// Linux, or anything else that brings its own virtio drivers.
    #[default]
    Linux,
    /// Windows, which needs virtio's drivers from a CD of their own, Hyper-V's
    /// enlightenments and a TPM, and has no waypipe.
    Windows,
}

impl System {
    /// The system's name, as `--system` takes it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Windows => "windows",
        }
    }
}

impl FromStr for System {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "linux" => Ok(Self::Linux),
            "windows" => Ok(Self::Windows),
            _ => Err(format!("`{name}` is not a system; linux or windows")),
        }
    }
}

/// A CD a machine starts with - an installer, or the drivers it needs - already on
/// this host. Installed once, like a template, and shared by every machine that
/// starts with the same bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Media {
    /// What it is called: its file's name, as a template is named.
    pub name: String,
    /// The image's SHA-256, in lowercase hex.
    pub digest: String,
    /// The image file.
    pub image: PathBuf,
    /// The image file's length in bytes.
    pub file_size: u64,
}

impl Media {
    /// The CD `image` is. Reads the whole image once, for its digest.
    ///
    /// # Errors
    ///
    /// The image cannot be read, or its file's name makes no usable name.
    pub fn from_image(image: &Path) -> miette::Result<Self> {
        let image = image
            .canonicalize()
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot find the CD image {}", image.display()))?;
        let mut file = File::open(&image)
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot open the CD image {}", image.display()))?;
        let file_size = file.metadata().into_diagnostic()?.len();
        let digest = digest_of(&mut file, &[])
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot read the CD image {}", image.display()))?;
        let name = name_of_image(&image);
        check_template_name(&name)
            .wrap_err_with(|| format!("rename {} to use it", image.display()))?;
        Ok(Self {
            name,
            digest,
            image,
            file_size,
        })
    }
}

/// What a machine's disk starts as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A copy-on-write layer over a template, ready to boot.
    Template(Template),
    /// Empty, with CDs to install `system` from: the machine boots the first
    /// once its disk has nothing to boot, and keeps them all until its owner
    /// takes them out.
    Installer {
        /// What it installs.
        system: System,
        /// The CDs, the one it boots from first.
        media: Vec<Media>,
    },
}

/// Fill as much of `buffer` as `file` holds, which is less only at its end.
fn read_up_to(file: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// A template name made from an image's file name: lowercase, the usual disk
/// extensions dropped, anything else a name cannot hold turned into `-`.
fn name_of_image(image: &Path) -> String {
    let file = image
        .file_name()
        .map(|name| name.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let stem = [".qcow2", ".raw", ".img", ".iso"]
        .into_iter()
        .find_map(|extension| file.strip_suffix(extension))
        .unwrap_or(&file);
    stem.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .take(64)
        .collect()
}

fn check_template_name(name: &str) -> miette::Result<()> {
    let usable = (1..=64).contains(&name.len())
        && !name.starts_with(['.', '-'])
        && name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        });
    if usable {
        Ok(())
    } else {
        Err(miette!(
            help = "name it with --template-name",
            "`{name}` cannot name a template: 1-64 characters of a-z, 0-9, `.`, `_` and `-`, \
             not starting with `.` or `-`"
        ))
    }
}

/// Check `name` can name a machine: 1-32 characters of `[a-z0-9]` and `-`, starting
/// with a letter.
///
/// Narrower than any hypervisor needs, because the name ends up in places with their
/// own rules - a volume's file name, a window's title, a Wayland security context -
/// and one this plain is safe in all of them.
///
/// # Errors
///
/// When it cannot.
pub fn check_machine_name(name: &str) -> miette::Result<()> {
    let usable = (1..=32).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if usable {
        Ok(())
    } else {
        Err(miette!(
            "`{name}` cannot name a machine: 1-32 characters of a-z, 0-9 and `-`, starting with \
             a letter"
        ))
    }
}

/// A machine to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    /// What it is called; see [`check_machine_name`].
    pub name: String,
    /// The colour its windows are framed in.
    pub label: Label,
    /// What its disk starts from.
    pub source: Source,
    /// The size of its disk, in bytes; never less than a template's.
    pub disk_size: u64,
    /// Memory, in MiB.
    pub memory_mib: u64,
    /// Virtual CPUs.
    pub cpus: u32,
    /// Whether the host has KVM.
    pub kvm: bool,
    /// The host's architecture, as Rust spells it.
    pub arch: String,
}

/// Something to do to the host's machines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Install the template or CDs unless they are installed, and make a stopped
    /// machine from them.
    Create(Spec),
    /// Print every machine.
    List,
    /// Start the named machine, unless it runs.
    Start(String),
    /// Ask the named machine to shut down, if it runs.
    Stop(String),
    /// Power the named machine off, if it runs.
    Kill(String),
    /// Power the named machine off and delete it and its disk.
    Remove(String),
}

impl Request {
    /// What the request does, for a log line or an error.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Create(spec) => format!("create the machine {}", spec.name),
            Self::List => "list the machines".into(),
            Self::Start(name) => format!("start the machine {name}"),
            Self::Stop(name) => format!("stop the machine {name}"),
            Self::Kill(name) => format!("power off the machine {name}"),
            Self::Remove(name) => format!("remove the machine {name}"),
        }
    }
}

/// One thing to run for a request; see [`carry_out`] for how steps run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// One line saying what it does.
    pub summary: String,
    /// What to run.
    pub run: Launch,
    /// Run the step only if this exits successfully.
    pub when: Option<Launch>,
    /// Skip the step if this exits successfully.
    pub unless: Option<Launch>,
    /// How to take the step back if a later one fails.
    pub undo: Option<Launch>,
}

/// Something that knows how a hypervisor carries out a [`Request`].
pub trait Manager {
    /// The steps that carry `request` out, in order.
    ///
    /// # Errors
    ///
    /// Nothing on the host manages machines, or the one that does refused the
    /// request.
    fn steps(&self, request: &Request) -> miette::Result<Vec<Step>>;
}

/// Carry `request` out: ask `manager` for its steps and run them.
///
/// Every step's conditions are run first, before any step, so the plan is fixed by
/// the state the host was in when the request was made: a request that creates a
/// template and then uploads into it would otherwise see the template it just created
/// and skip the upload. Then the steps that are still in the plan run in order, each
/// with pm's standard output and error, and the first that fails stops the request;
/// the `undo`s of the steps that had finished run then, newest first, so a half-made
/// machine does not stay behind to be mistaken for a whole one. Not the failed step's
/// own undo: a step that failed is taken to have changed nothing, and undoing it
/// could delete what made it fail, such as another machine's disk of the same name.
///
/// Each launch runs in a directory of its own, private to the user, holding the
/// files it asked for, so its arguments name them by their bare names.
///
/// # Errors
///
/// The manager refused, a program is missing, or a step failed.
pub fn carry_out(manager: &dyn Manager, request: &Request) -> miette::Result<()> {
    let steps = manager.steps(request)?;
    let scratch = tempfile::Builder::new()
        .prefix("pm-machine-")
        .tempdir()
        .into_diagnostic()
        .wrap_err("cannot make a directory for the request's files")?;
    fs::set_permissions(scratch.path(), fs::Permissions::from_mode(0o700)).into_diagnostic()?;
    let mut runner = Runner {
        root: scratch.path(),
        next: 0,
    };

    // The plan, fixed before anything runs. A question asked of the same state has
    // the same answer, so each distinct probe runs once however many steps ask it.
    let mut answers: Vec<(&Launch, bool)> = Vec::new();
    let mut ask = |runner: &mut Runner<'_>, probe| -> miette::Result<bool> {
        if let Some((_, answer)) = answers.iter().find(|(asked, _)| *asked == probe) {
            return Ok(*answer);
        }
        let answer = runner.probe(probe)?;
        answers.push((probe, answer));
        Ok(answer)
    };
    let mut plan = Vec::with_capacity(steps.len());
    for step in &steps {
        let wanted = match &step.when {
            Some(probe) => ask(&mut runner, probe)?,
            None => true,
        } && match &step.unless {
            Some(probe) => !ask(&mut runner, probe)?,
            None => true,
        };
        if !wanted {
            debug!(step = %step.summary, "not needed");
        }
        plan.push(wanted);
    }

    let mut done: Vec<&Step> = Vec::new();
    for (step, wanted) in steps.iter().zip(plan) {
        if !wanted {
            continue;
        }
        info!("{}", step.summary);
        if let Err(error) = runner.run(&step.run) {
            for finished in done.iter().rev() {
                if let Some(undo) = &finished.undo
                    && let Err(undo_error) = runner.run(undo)
                {
                    warn!(
                        step = %finished.summary,
                        error = %undo_error,
                        "cannot take the step back"
                    );
                }
            }
            return Err(error)
                .wrap_err_with(|| format!("cannot {}: {}", request.describe(), step.summary));
        }
        done.push(step);
    }
    Ok(())
}

/// Runs a request's launches, each in a directory of its own under `root`.
struct Runner<'a> {
    root: &'a Path,
    next: usize,
}

impl Runner<'_> {
    /// A command for `launch` in a fresh directory holding its files.
    fn command(&mut self, launch: &Launch) -> miette::Result<Command> {
        let directory = self.root.join(self.next.to_string());
        self.next += 1;
        DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .into_diagnostic()?;
        for file in &launch.files {
            write_file(&directory, file)?;
        }
        let program = if launch.program.components().count() > 1 {
            launch.program.clone()
        } else {
            let name = launch.program.to_string_lossy();
            find_on_path(&name).ok_or_else(|| {
                miette!(
                    help = "install it, or install a different plugin to manage machines",
                    "{} manages machines with {name}, which is not on PATH",
                    launch.by
                )
            })?
        };
        let mut command = Command::new(program);
        command
            .args(&launch.args)
            .current_dir(directory)
            .stdin(Stdio::null());
        Ok(command)
    }

    /// Whether `probe` exits successfully. What it prints is nobody's business: a
    /// probe asks a question, and its answer is its exit status.
    fn probe(&mut self, probe: &Launch) -> miette::Result<bool> {
        let status = self
            .command(probe)?
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot run {}", probe.program.display()))?;
        Ok(status.success())
    }

    fn run(&mut self, launch: &Launch) -> miette::Result<()> {
        let status = self
            .command(launch)?
            .status()
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot run {}", launch.program.display()))?;
        if status.success() {
            Ok(())
        } else {
            Err(miette!(
                "{} {} {status}",
                launch.program.display(),
                launch.args.join(" ")
            ))
        }
    }
}

/// Whether the host has KVM for a hypervisor to use.
///
/// Whether the device exists, not whether this process can open it: the
/// hypervisor that runs the machines - libvirt's system daemon, say - is usually
/// not this process, and can open what this user cannot.
#[must_use]
pub fn host_has_kvm() -> bool {
    Path::new("/dev/kvm").exists()
}

/// Where a host's packages put the CD a machine installing `system` is given
/// after its own: `pm/machines/<system>-tools.iso` under one of the XDG data
/// directories.
#[must_use]
pub fn guest_tools_path(system: System) -> String {
    format!("pm/machines/{}-tools.iso", system.name())
}

/// The CD of guest tools the host's packages installed for machines that install
/// `system`: the first [`guest_tools_path`] under `$XDG_DATA_DIRS`, or under the
/// specification's own default directories when that is unset.
///
/// What is on it is the host's business, because it is what makes a guest fit
/// the host's desktop: for Windows the virtio drivers Setup has none of and the
/// answer file that loads them, for Linux what sends a distribution's windows to
/// the desktop. pm knows only where to look.
#[must_use]
pub fn guest_tools(system: System) -> Option<PathBuf> {
    let dirs = std::env::var_os("XDG_DATA_DIRS")
        .filter(|dirs| !dirs.is_empty())
        .unwrap_or_else(|| "/usr/local/share:/usr/share".into());
    let path = guest_tools_path(system);
    std::env::split_paths(&dirs)
        .map(|dir| dir.join(&path))
        .find(|cd| cd.is_file())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn a_qcow2_image_has_the_size_its_header_says() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Guest Image.qcow2");
        let mut header = vec![0u8; 512];
        header[..4].copy_from_slice(&QCOW2_MAGIC);
        header[4..8].copy_from_slice(&3u32.to_be_bytes());
        header[24..32].copy_from_slice(&(20u64 << 30).to_be_bytes());
        File::create(&path).unwrap().write_all(&header).unwrap();

        let template = Template::from_image(&path, None, Firmware::Uefi).unwrap();
        assert_eq!(template.name, "guest-image");
        assert_eq!(template.format, DiskFormat::Qcow2);
        assert_eq!(template.file_size, 512);
        assert_eq!(template.disk_size, 20 << 30);
        assert_eq!(template.digest.len(), 64);
    }

    #[test]
    fn a_raw_image_is_as_big_as_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.img");
        File::create(&path).unwrap().write_all(&[7; 4096]).unwrap();

        let template = Template::from_image(&path, Some("base"), Firmware::Bios).unwrap();
        assert_eq!(template.name, "base");
        assert_eq!(template.format, DiskFormat::Raw);
        assert_eq!(template.disk_size, 4096);
        assert_eq!(template.firmware, Firmware::Bios);
    }

    #[test]
    fn the_same_bytes_have_the_same_digest() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        fs::write(&a, b"one").unwrap();
        fs::write(&b, b"one").unwrap();
        let digest = |path: &Path| {
            Template::from_image(path, Some("t"), Firmware::Uefi)
                .unwrap()
                .digest
        };
        assert_eq!(digest(&a), digest(&b));
        fs::write(&b, b"two").unwrap();
        assert_ne!(digest(&a), digest(&b));
    }

    #[test]
    fn a_cut_qcow2_header_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cut.qcow2");
        fs::write(&path, QCOW2_MAGIC).unwrap();
        assert!(Template::from_image(&path, None, Firmware::Uefi).is_err());
    }

    #[test]
    fn machine_names_are_plain() {
        for good in ["work", "a", "personal-2", "x".repeat(32).as_str()] {
            check_machine_name(good).unwrap();
        }
        for bad in [
            "",
            "Work",
            "2work",
            "-work",
            "work_1",
            "wörk",
            &"x".repeat(33),
        ] {
            assert!(check_machine_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_cd_is_named_after_its_file_and_known_by_its_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Win11_24H2_English_x64.iso");
        fs::write(&path, [1u8; 2048]).unwrap();
        let media = Media::from_image(&path).unwrap();
        assert_eq!(media.name, "win11_24h2_english_x64");
        assert_eq!(media.file_size, 2048);
        assert_eq!(media.digest.len(), 64);
        assert!(Media::from_image(&dir.path().join("missing.iso")).is_err());
    }

    #[test]
    fn systems_round_trip() {
        for system in [System::Linux, System::Windows] {
            assert_eq!(system.name().parse::<System>(), Ok(system));
        }
        assert!("macos".parse::<System>().is_err());
    }

    #[test]
    fn labels_round_trip() {
        for label in Label::ALL {
            assert_eq!(label.name().parse::<Label>(), Ok(label));
        }
        assert!("pink".parse::<Label>().is_err());
    }
}

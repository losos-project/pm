//! Turning what a plugin said into something pm is willing to act on.
//!
//! Everything crossing back from a plugin passes through here, and nothing reaches the
//! rest of the crate as the generated type it arrived as. That is deliberate: a plugin
//! is code somebody else wrote, and the component model only guarantees that its
//! answers have the right *shape*. It says nothing about whether the shape is filled
//! with a usable name, a path that is not empty, or a capability the plugin said it
//! would never ask for.
//!
//! The rules are all of the "reject or trim, never fail the build" kind. A plugin that
//! returns nonsense loses the nonsense and gets a `warn` line naming it; it does not get
//! to stop a package from building, because a plugin that can fail a build at will is a
//! plugin that can hold a build hostage.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use tracing::warn;

use super::{
    Hook, Manifest, RecipeFunction, RecipeValue, Symbol,
    wit::{
        WitCapability, WitContainerPlace, WitContainerRequest, WitDiskFormat, WitFirmware,
        WitGrant, WitGuestSystem, WitHook, WitLaunch, WitMachine, WitMachineInstaller,
        WitMachineLabel, WitMachineMedia, WitMachinePlace, WitMachineRequest, WitMachineSource,
        WitMachineSpec, WitMachineStep, WitMachineTemplate, WitManifest, WitPermission,
        WitRecipeFunction, WitRecipeValue, WitSymbol, WitVerdict,
    },
};
use crate::{
    container::{Place as ContainerPlace, Request as ContainerRequest},
    machine::{
        DiskFormat, Firmware, Label, Media, Place, Request, Source, Spec, Step, System, Template,
    },
    perms::{Grant, Permission, Provenance},
    policy::Capability,
};

/// Longest a plugin name or a fingerprint name may be.
///
/// Both end up in a column of `pm explain` or `pm plugins`, and both are meant to be
/// read at a glance.
const NAME_MAX: usize = 32;

/// Longest a version string may be. Shown, never parsed.
const VERSION_MAX: usize = 32;

/// Longest a one-line summary may be.
const SUMMARY_MAX: usize = 200;

/// Longest a file extension may be, without the dot.
const EXTENSION_MAX: usize = 16;

/// Longest an evidence line from a plugin may be.
///
/// The house format is one locator plus one reason; anything longer is a plugin
/// printing its own debugging into the permission report.
const EVIDENCE_MAX: usize = 200;

/// Longest a path in a plugin's grant may be.
const PATH_MAX: usize = 4096;

/// Longest the value of a symbol may be.
///
/// Generously more than any path a build file would name, and short enough that a
/// plugin cannot bury a command line under one substitution.
const SYMBOL_VALUE_MAX: usize = 1024;

/// How many symbols one plugin may publish.
///
/// `pm plugins` prints every one of them, and a list nobody reads is a list nobody is
/// holding the plugin to.
const SYMBOLS_MAX: usize = 64;

/// How many recipe functions one plugin may add. As with symbols, `pm plugins` prints
/// them all.
const RECIPE_FUNCTIONS_MAX: usize = 64;

/// Most parameters a recipe function may take.
pub(crate) const RECIPE_PARAMS_MAX: usize = 6;

/// Longest the documentation of a recipe function may be.
const DOC_MAX: usize = 2000;

/// How many grants one `scan-source` call may contribute.
///
/// A file yielding more than this is a plugin with a runaway query, not a file with
/// sixty-five genuinely distinct permissions in it.
pub(super) const MAX_GRANTS_PER_FILE: usize = 64;

/// Read the manifest a plugin describes itself with, rejecting the parts pm cannot use.
///
/// The name is the one hard requirement: it prefixes every fingerprint the plugin
/// contributes and tags every log line and evidence line it causes, so a plugin without
/// a usable one has no way to be attributed and is refused outright. Everything else is
/// trimmed to size or dropped with a warning.
///
/// # Errors
///
/// Returns the reason as a string when the name is missing or malformed. That is the
/// only way this fails, and it fails at load time, where refusing a plugin is a
/// configuration error the user can see and fix.
pub(super) fn manifest(from: WitManifest, file: &str) -> Result<Manifest, String> {
    let name = name(&from.name).ok_or_else(|| {
        format!(
            "the plugin in {file} calls itself {:?}, which is not a usable name: \
             1 to {NAME_MAX} characters of a-z, 0-9 and `-`, at least one of them not `-`",
            from.name
        )
    })?;

    let hooks: BTreeSet<Hook> = from.hooks.into_iter().map(hook).collect();
    if hooks.is_empty() {
        warn!(
            plugin = %name,
            "declares no hooks, so it will never be called; it is loaded only to be listed"
        );
    }

    let grants_at_most: Vec<Capability> = {
        let mut set: BTreeSet<Capability> =
            from.grants_at_most.into_iter().map(capability).collect();
        // A ceiling nobody will ever be measured against is noise in `pm plugins`.
        if !hooks.contains(&Hook::ClassifyCommand) {
            set.clear();
        }
        set.into_iter().collect()
    };

    let source_extensions = if hooks.contains(&Hook::ScanSource) {
        from.source_extensions
            .into_iter()
            .filter_map(|raw| {
                extension(&raw).or_else(|| {
                    warn!(plugin = %name, extension = %raw, "not a usable file extension; ignored");
                    None
                })
            })
            .collect()
    } else {
        BTreeSet::new()
    };

    let symbols = symbols(from.symbols, &name);

    Ok(Manifest {
        name,
        version: clip(from.version, VERSION_MAX),
        summary: clip(from.summary, SUMMARY_MAX),
        hooks,
        grants_at_most,
        source_extensions,
        symbols,
        recipe_functions: BTreeMap::new(),
        launchers: BTreeSet::new(),
        manages_machines: false,
        manages_containers: false,
    })
}

/// The most programs a plugin may list in `launchers`: few enough to read at a
/// glance under `pm plugins`, and enough for a plugin that keeps machines as plain
/// files, as `quickemu` does, to name each coreutil it moves them with rather than
/// one shell that could run anything.
const LAUNCHERS_MAX: usize = 12;

/// Read the programs a `vm-plugin` may have pm run, dropping any that is not a bare
/// program name.
///
/// A bare name, so that what `pm plugins` prints is what runs: a path could point
/// anywhere, and pm finds the name on `PATH` the way a shell would. At most
/// [`NAME_MAX`] characters of letters, digits, `.`, `_`, `+` and `-`, not starting
/// with `.` or `-`.
pub(super) fn launchers(from: Vec<String>, plugin: &str) -> BTreeSet<String> {
    let mut kept = BTreeSet::new();
    for name in from {
        let usable = !name.is_empty()
            && name.len() <= NAME_MAX
            && !name.starts_with(['.', '-'])
            && name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-')
            });
        if !usable {
            warn!(plugin, launcher = %name, "not a bare program name; ignoring it");
            continue;
        }
        if kept.len() == LAUNCHERS_MAX {
            warn!(
                plugin,
                "lists more than {LAUNCHERS_MAX} launchers; the rest were dropped"
            );
            break;
        }
        kept.insert(name);
    }
    kept
}

/// The machine as the `vm-plugin` world spells it.
pub(super) fn machine(from: &pm_vm::Machine<'_>) -> WitMachine {
    let text = |path: &std::path::Path| path.to_string_lossy().into_owned();
    WitMachine {
        name: from.name.to_owned(),
        title: from.title.to_owned(),
        directory: text(from.directory),
        kernel: text(from.kernel),
        initramfs: text(from.initramfs),
        cmdline: from.cmdline.to_owned(),
        memory_mib: from.memory_mib,
        cpus: u32::try_from(from.cpus).unwrap_or(u32::MAX),
        kvm: from.kvm,
        status_socket: text(from.status_socket),
    }
}

/// A plugin's launch, checked against the programs it listed.
///
/// # Errors
///
/// The program is not one of `launchers`, or an argument holds a NUL byte, which no
/// program could be handed.
pub(super) fn launch(
    from: WitLaunch,
    plugin: &str,
    launchers: &BTreeSet<String>,
) -> std::result::Result<pm_vm::Launch, String> {
    if !launchers.contains(&from.program) {
        return Err(format!(
            "the plugin {plugin} asked pm to run `{}`, which is not among the launchers it \
             listed ({})",
            from.program,
            launchers.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    if from.args.iter().any(|arg| arg.contains('\0')) {
        return Err(format!(
            "the plugin {plugin} gave {} an argument with a NUL byte",
            from.program
        ));
    }
    Ok(pm_vm::Launch {
        by: plugin.to_owned(),
        program: from.program.into(),
        args: from.args,
        files: from
            .files
            .into_iter()
            .map(|file| pm_vm::LaunchFile {
                name: file.name,
                contents: file.contents.into_bytes(),
            })
            .collect(),
    })
}

/// Read the functions a plugin adds to recipes, dropping the ones a recipe could not
/// call.
///
/// The name has to be one Rhai parses as a function name (so not a keyword), at most
/// [`NAME_MAX`] characters of `a-z`, `0-9` and `_`; the arity at most
/// [`RECIPE_PARAMS_MAX`]. A second function with a name already taken is dropped too:
/// a recipe function is called by name and arity, and two with the same name would
/// make which one runs depend on how many arguments a typo supplied.
pub(super) fn recipe_functions(
    from: Vec<WitRecipeFunction>,
    plugin: &str,
) -> BTreeMap<String, RecipeFunction> {
    let offered = from.len();
    let mut kept = BTreeMap::new();
    for raw in from {
        let usable = !raw.name.is_empty()
            && raw.name.len() <= NAME_MAX
            && raw
                .name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            && rhai::is_valid_function_name(&raw.name);
        if !usable {
            warn!(plugin, function = %raw.name, "not a usable recipe function name; ignoring it");
            continue;
        }
        if raw.params.len() > RECIPE_PARAMS_MAX {
            warn!(
                plugin,
                function = %raw.name,
                params = raw.params.len(),
                "takes more than {RECIPE_PARAMS_MAX} parameters; ignoring it"
            );
            continue;
        }
        if kept.contains_key(&raw.name) {
            warn!(plugin, function = %raw.name, "is listed twice; ignoring the second");
            continue;
        }
        if kept.len() == RECIPE_FUNCTIONS_MAX {
            warn!(
                plugin,
                offered, "adds more recipe functions than pm records; the rest were dropped"
            );
            break;
        }
        let returns = match raw.returns {
            WitRecipeValue::Any => RecipeValue::Any,
            WitRecipeValue::Step => RecipeValue::Step,
            WitRecipeValue::Steps => RecipeValue::Steps,
            WitRecipeValue::Kernel => RecipeValue::Kernel,
            WitRecipeValue::Package => RecipeValue::Package,
        };
        // Parameter names only document the function, but they land in `pm plugins`
        // and in `pm-lsp --definitions`, so one that is not an identifier becomes
        // `argN` rather than text a definitions file cannot parse.
        let params = raw
            .params
            .into_iter()
            .enumerate()
            .map(|(index, param)| {
                if param.len() <= NAME_MAX && rhai::is_valid_identifier(&param) {
                    param
                } else {
                    warn!(
                        plugin,
                        function = %raw.name,
                        param = %param,
                        "not a usable parameter name; calling it arg{}",
                        index + 1
                    );
                    format!("arg{}", index + 1)
                }
            })
            .collect();
        kept.insert(
            raw.name.clone(),
            RecipeFunction {
                name: raw.name,
                params,
                returns,
                doc: clip(raw.doc, DOC_MAX),
            },
        );
    }
    kept
}

/// Read the named constants a plugin publishes, dropping the ones pm will not
/// substitute into a command.
///
/// Two rules, and the second is the one that matters:
///
/// * **the name has to be usable**, because a build file refers to the symbol by it and
///   a diagnostic has to be able to name it back;
/// * **the value has to be a single word.** A step command is split on whitespace and
///   handed straight to `execve` with no shell in between, so a value holding
///   whitespace would not be substituted *into* an argument - it would add arguments.
///   `install -Dm644 foo %{p:dir}/foo` with `dir` = `/tmp --strip-all /etc/shadow` is a
///   different command from the one the build file's author wrote and signed. Control
///   characters and NULs go for the same reason: nothing legitimate puts them in a path,
///   and both are how an argument stops meaning what it looks like it means.
///
/// A dropped symbol is logged and then simply does not exist, so a build file naming it
/// fails with "no plugin offers this symbol" rather than quietly running something else.
fn symbols(from: Vec<WitSymbol>, plugin: &str) -> BTreeMap<String, Symbol> {
    let offered = from.len();
    let kept: BTreeMap<String, Symbol> = from
        .into_iter()
        .filter_map(|raw| {
            let Some(name) = symbol_name(&raw.name) else {
                warn!(
                    plugin,
                    symbol = %raw.name,
                    "not a usable symbol name; ignoring it"
                );
                return None;
            };
            if !is_one_word(&raw.value) {
                warn!(
                    plugin,
                    symbol = %name,
                    bytes = raw.value.len(),
                    "the value is empty, over-long, or holds whitespace, a control \
                     character or a NUL; a step command is split on whitespace, so \
                     substituting it would add arguments rather than fill one in. \
                     Ignoring the symbol."
                );
                return None;
            }
            Some((
                name.clone(),
                Symbol {
                    name,
                    value: raw.value,
                    summary: clip(raw.summary, SUMMARY_MAX),
                },
            ))
        })
        .take(SYMBOLS_MAX)
        .collect();

    if offered > SYMBOLS_MAX {
        warn!(
            plugin,
            offered,
            kept = kept.len(),
            "publishes more symbols than pm records; the rest were dropped"
        );
    }
    kept
}

/// A symbol name, if `raw` is one.
///
/// As [`name`], plus `_`: these read as identifiers rather than as command words, and
/// `unit_dir` is a spelling somebody will reach for.
fn symbol_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let usable = !trimmed.is_empty()
        && trimmed.len() <= NAME_MAX
        && trimmed.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
        && trimmed.bytes().any(|byte| byte.is_ascii_alphanumeric());
    usable.then(|| trimmed.to_owned())
}

/// Whether `value` is something pm will substitute into one argument of a command.
fn is_one_word(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= SYMBOL_VALUE_MAX
        && !value.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Read a classification verdict, holding the plugin to the ceiling it declared.
///
/// Two things can happen to a verdict here:
///
/// * **the fingerprint name is unusable** - the verdict is dropped whole, because a
///   grant pm cannot name is a grant pm cannot explain, and `pm explain` exists
///   precisely so that nothing in a policy is anonymous;
/// * **it asks for a capability outside [`Manifest::grants_at_most`]** - that capability
///   is dropped and the rest of the verdict stands. The ceiling is the plugin's own
///   published claim about itself, and holding it to that claim is what makes reading
///   `pm plugins` a substitute for reading the plugin.
///
/// Both are logged at `warn` against the plugin's name.
///
/// The name comes back prefixed with the plugin's own, so a plugin's fingerprint reads
/// `zig:zig-build` in `pm explain` and can never be mistaken for a built-in.
pub(super) fn verdict(from: WitVerdict, manifest: &Manifest) -> Option<(String, Vec<Capability>)> {
    let Some(fingerprint) = name(&from.fingerprint) else {
        warn!(
            plugin = %manifest.name,
            fingerprint = %from.fingerprint,
            "returned a verdict whose fingerprint name is not usable; ignoring the verdict"
        );
        return None;
    };

    let capabilities = from
        .capabilities
        .into_iter()
        .map(capability)
        .filter(|wanted| {
            let allowed = manifest.grants_at_most.contains(wanted);
            if !allowed {
                warn!(
                    plugin = %manifest.name,
                    capability = ?wanted,
                    ceiling = ?manifest.grants_at_most,
                    "asked for a capability outside the ceiling it published; dropping it"
                );
            }
            allowed
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    Some((format!("{}:{fingerprint}", manifest.name), capabilities))
}

/// Read the grants a `scan-source` call produced, dropping the unusable ones.
///
/// Each surviving grant is stamped [`Provenance::Plugin`] and its evidence line is
/// rewritten to lead with the file and name the plugin, so the permission report answers
/// "who asked for this, and about what?" without anyone having to correlate two columns.
/// At most [`MAX_GRANTS_PER_FILE`] survive one call.
pub(super) fn grants(from: Vec<WitGrant>, manifest: &Manifest, relative: &str) -> Vec<Grant> {
    let produced = from.len();
    let kept: Vec<Grant> = from
        .into_iter()
        .filter_map(|raw| {
            let permission = permission(raw.permission, manifest)?;
            let reason = clip(raw.evidence.replace(['\n', '\r'], " "), EVIDENCE_MAX);
            Some(Grant::new(
                permission,
                Provenance::Plugin,
                [format!("{relative}: {}: {reason}", manifest.name)],
            ))
        })
        .take(MAX_GRANTS_PER_FILE)
        .collect();

    // Only when the cap is what stopped it. A plugin returning ninety unusable grants
    // and ten good ones was not truncated, it was filtered, and saying otherwise sends
    // the reader looking for grants that were never there.
    if kept.len() == MAX_GRANTS_PER_FILE && produced > MAX_GRANTS_PER_FILE {
        warn!(
            plugin = %manifest.name,
            file = %relative,
            produced,
            kept = kept.len(),
            "returned more grants for one file than pm records; the rest were dropped"
        );
    }
    kept
}

/// Read one permission, or `None` when its path is not one pm can record.
///
/// An empty path would normalise to the current directory and quietly grant the whole
/// build tree; an over-long one and one holding a NUL are both things that cannot come
/// from a real source file and can only make trouble further down.
fn permission(from: WitPermission, manifest: &Manifest) -> Option<Permission> {
    let with_path = |raw: String, build: fn(PathBuf) -> Permission| {
        if raw.is_empty() || raw.len() > PATH_MAX || raw.contains('\0') {
            warn!(
                plugin = %manifest.name,
                bytes = raw.len(),
                "asked for a path that is empty, over-long or holds a NUL; dropping the grant"
            );
            return None;
        }
        Some(build(PathBuf::from(raw)))
    };

    match from {
        WitPermission::ReadPath(path) => with_path(path, Permission::ReadPath),
        WitPermission::WritePath(path) => with_path(path, Permission::WritePath),
        WitPermission::ExecPath(path) => with_path(path, Permission::ExecPath),
        WitPermission::Network => Some(Permission::Network),
        WitPermission::Spawn => Some(Permission::Spawn),
    }
}

/// Map a capability across the boundary. Total in both directions by construction: the
/// WIT enum is the Rust one, written out again.
pub(super) fn capability(from: WitCapability) -> Capability {
    match from {
        WitCapability::Toolchain => Capability::Toolchain,
        WitCapability::Coreutils => Capability::Coreutils,
        WitCapability::Shell => Capability::Shell,
        WitCapability::Archive => Capability::Archive,
        WitCapability::Network => Capability::Network,
        WitCapability::VersionControl => Capability::VersionControl,
    }
}

/// Map a hook across the boundary.
fn hook(from: WitHook) -> Hook {
    match from {
        WitHook::ClassifyCommand => Hook::ClassifyCommand,
        WitHook::ScanSource => Hook::ScanSource,
    }
}

/// A plugin or fingerprint name, if `raw` is one.
///
/// The charset is narrow on purpose. These names are printed in aligned tables,
/// interpolated into evidence lines and used as a prefix separated by `:`, so anything
/// holding whitespace, a colon, a control character or a right-to-left override would
/// either break the layout or make one plugin's output look like another's.
fn name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let usable = !trimmed.is_empty()
        && trimmed.len() <= NAME_MAX
        && trimmed
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && trimmed.bytes().any(|byte| byte != b'-');
    usable.then(|| trimmed.to_owned())
}

/// A file extension, without the dot, if `raw` is one.
fn extension(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_start_matches('.').to_ascii_lowercase();
    let usable = !trimmed.is_empty()
        && trimmed.len() <= EXTENSION_MAX
        && trimmed.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || byte == b'_'
                || byte == b'+'
                || byte == b'-'
        });
    usable.then_some(trimmed)
}

/// Cut `text` to `max` characters on a character boundary, marking the cut.
fn clip(text: String, max: usize) -> String {
    if text.chars().count() <= max {
        return text;
    }
    let mut out: String = text.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// A request about the host's machines as the `machine-plugin` world spells it.
pub(super) fn machine_request(from: &Request) -> WitMachineRequest {
    match from {
        Request::Create(spec) => WitMachineRequest::Create(machine_spec(spec)),
        Request::List => WitMachineRequest::List,
        Request::Start(name) => WitMachineRequest::Start(name.clone()),
        Request::Stop(name) => WitMachineRequest::Stop(name.clone()),
        Request::Kill(name) => WitMachineRequest::Kill(name.clone()),
        Request::Remove(name) => WitMachineRequest::Remove(name.clone()),
    }
}

/// A request about the asking user's containers as the `container-plugin` world
/// spells it. pm checked every name and made every file absolute, and an absolute
/// path pm found is UTF-8 ([`crate::container::compose_file`]).
pub(super) fn container_request(from: &ContainerRequest) -> WitContainerRequest {
    let file = |path: &std::path::Path| path.to_string_lossy().into_owned();
    match from {
        ContainerRequest::List => WitContainerRequest::List,
        ContainerRequest::Status(name) => WitContainerRequest::Status(name.clone()),
        ContainerRequest::Ports(name) => WitContainerRequest::Ports(name.clone()),
        ContainerRequest::Up(path) => WitContainerRequest::Up(file(path)),
        ContainerRequest::Create(path) => WitContainerRequest::Create(file(path)),
        ContainerRequest::Down(path) => WitContainerRequest::Down(file(path)),
        ContainerRequest::Start(name) => WitContainerRequest::Start(name.clone()),
        ContainerRequest::Stop(name) => WitContainerRequest::Stop(name.clone()),
        ContainerRequest::Pause(name) => WitContainerRequest::Pause(name.clone()),
        ContainerRequest::Unpause(name) => WitContainerRequest::Unpause(name.clone()),
        ContainerRequest::Remove(name) => WitContainerRequest::Remove(name.clone()),
        ContainerRequest::Version => WitContainerRequest::Version,
    }
}

/// Whose containers a request is about, as the `container-plugin` world spells it.
pub(super) const fn container_place(from: &ContainerPlace) -> WitContainerPlace {
    WitContainerPlace {
        rootless: from.rootless,
    }
}

/// Where the asking user's machines are, as the `machine-plugin` world spells it.
pub(super) fn machine_place(from: &Place) -> WitMachinePlace {
    WitMachinePlace {
        directory: from.directory.to_string_lossy().into_owned(),
        user_manager: from.user_manager,
        random: from.random.to_vec(),
    }
}

fn machine_spec(from: &Spec) -> WitMachineSpec {
    WitMachineSpec {
        name: from.name.clone(),
        label: match from.label {
            Label::Red => WitMachineLabel::Red,
            Label::Orange => WitMachineLabel::Orange,
            Label::Yellow => WitMachineLabel::Yellow,
            Label::Green => WitMachineLabel::Green,
            Label::Gray => WitMachineLabel::Gray,
            Label::Blue => WitMachineLabel::Blue,
            Label::Purple => WitMachineLabel::Purple,
            Label::Black => WitMachineLabel::Black,
        },
        source: match &from.source {
            Source::Template(template) => WitMachineSource::Template(machine_template(template)),
            Source::Installer { system, media } => {
                WitMachineSource::Installer(WitMachineInstaller {
                    system: match system {
                        System::Linux => WitGuestSystem::Linux,
                        System::Windows => WitGuestSystem::Windows,
                    },
                    media: media.iter().map(machine_media).collect(),
                })
            }
        },
        disk_size: from.disk_size,
        memory_mib: from.memory_mib,
        cpus: from.cpus,
        kvm: from.kvm,
        arch: from.arch.clone(),
    }
}

fn machine_template(from: &Template) -> WitMachineTemplate {
    WitMachineTemplate {
        name: from.name.clone(),
        digest: from.digest.clone(),
        image: from.image.to_string_lossy().into_owned(),
        format: match from.format {
            DiskFormat::Raw => WitDiskFormat::Raw,
            DiskFormat::Qcow2 => WitDiskFormat::Qcow2,
        },
        file_size: from.file_size,
        disk_size: from.disk_size,
        firmware: match from.firmware {
            Firmware::Uefi => WitFirmware::Uefi,
            Firmware::Bios => WitFirmware::Bios,
        },
    }
}

fn machine_media(from: &Media) -> WitMachineMedia {
    WitMachineMedia {
        name: from.name.clone(),
        digest: from.digest.clone(),
        image: from.image.to_string_lossy().into_owned(),
        file_size: from.file_size,
    }
}

/// A plugin's steps for a request, every launch in them checked against the programs
/// it listed, as a machine's launch is.
///
/// # Errors
///
/// A step names a program outside `launchers`, or an argument with a NUL byte.
pub(super) fn machine_steps(
    from: Vec<WitMachineStep>,
    plugin: &str,
    launchers: &BTreeSet<String>,
) -> std::result::Result<Vec<Step>, String> {
    let check = |launched: WitLaunch| launch(launched, plugin, launchers);
    let optional = |launched: Option<WitLaunch>| launched.map(check).transpose();
    from.into_iter()
        .map(|step| {
            Ok(Step {
                summary: clip(step.summary, SUMMARY_MAX),
                run: check(step.run)?,
                when: optional(step.when)?,
                unless: optional(step.unless)?,
                undo: optional(step.undo)?,
            })
        })
        .collect()
}

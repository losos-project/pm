use clap::{Parser, Subcommand};
use miette::{IntoDiagnostic, WrapErr, miette};
use pm::{
    bf::{BuildFile, BuildOptions},
    machine::{
        Firmware, Label, Media, Request as MachineRequest, Source, Spec, System, Template,
        carry_out, check_machine_name, guest_tools, guest_tools_path, host_has_kvm,
    },
    metadata::Metadata,
    migrate,
    perms::Enforcement,
    plugin::{Loader, Registry, Trust, default_plugin_dir},
    policy::{BuildPolicy, Capability, UNMATCHED},
    progress::Progress,
    recipe,
    run::PackageRunner,
    sandbox::CONTAINER_WORKDIR,
    signing::{
        Signature, SigningKey, TrustStore, default_key_path, default_trust_dir, sign_file,
        verify_file,
    },
    star,
    step::Step,
    system::Verb,
    text::comma_join,
    workspace::Workspace,
};
use serde::Serialize;
use serde_yaml::{Value, from_str, to_string, to_value};
use std::{
    ffi::OsString,
    fs::{OpenOptions, read_to_string, remove_file, rename, write},
    io::{ErrorKind, Write as _},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::Command,
};
use tracing::{info, warn};
use tracing_subscriber::{EnvFilter, fmt};
use url::Url;

/// Width the labels of the key/value blocks are padded to, so their values
/// line up under each other.
const LABEL_WIDTH: usize = 12;

/// Header of the command column `pm explain` prints.
const COMMAND_HEADER: &str = "COMMAND";

/// Width the symbol column of `pm explain` is padded to.
///
/// Wide enough for `%{plugin:name}` at the name lengths the plugin loader allows,
/// without pushing the value column off a terminal.
const SYMBOL_WIDTH: usize = 34;

/// Widest the command column is padded to. A longer command is not truncated -
/// the row simply runs past the column - because a build file is something the
/// user has to be able to read back verbatim.
const COMMAND_WIDTH_CAP: usize = 72;

/// Name of the metadata member at the root of every `.cpkg` archive.
const METADATA_MEMBER: &str = "metadata";

/// Suffix of the detached signature that travels beside a package.
const SIGNATURE_SUFFIX: &str = ".sig";

/// Suffix `pm promote` renames a signature to once it has rewritten the archive
/// out from under it. The file is kept rather than deleted so the old signer is
/// still on record, but the name says plainly that it can never verify again.
const STALE_SIGNATURE_SUFFIX: &str = ".sig.stale";

/// Suffix of the archive `pm promote` builds beside the package before renaming
/// it over the original. Written next to the package rather than in the
/// workspace so the rename is within one filesystem and cannot fail half-way.
const PROMOTED_SUFFIX: &str = ".promoting";

#[derive(Parser)]
#[clap(name = "pm", version, about = "A package manager")]
#[command(subcommand_required = true, arg_required_else_help = true)]
struct Arge {
    #[command(subcommand)]
    command: Commands,

    /// Log every step, and let build commands write to the terminal directly.
    ///
    /// Turns off the live progress display. A build command's output is then
    /// inherited rather than captured, which is what you want when you are
    /// reading a build rather than watching it.
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(flatten)]
    plugins: PluginArgs,
}

/// Where pm looks for plugins and how strictly it reads them.
///
/// Global, because the same three answers have to hold for `pm build`, `pm explain` and
/// `pm plugins` alike: `explain` exists to show what `build` will do, and it cannot do
/// that from a different plugin set.
#[derive(clap::Args, Debug, Clone)]
struct PluginArgs {
    /// Do not load any installed plugins.
    ///
    /// pm then classifies commands and scans sources with nothing but its own
    /// bundled plugins, which is exactly what it did before plugins could be
    /// installed. The honest way to find out whether an installed plugin is
    /// responsible for a surprising policy.
    #[arg(long, global = true)]
    no_plugins: bool,

    /// Load plugins from this directory instead of `<config>/pm/plugins`.
    #[arg(long, global = true, value_name = "DIR")]
    plugin_dir: Option<PathBuf>,

    /// Load plugins WITHOUT verifying their signatures.
    ///
    /// A plugin runs inside pm, with your privileges, and helps decide what a
    /// build jail allows. This is for developing one you have not signed yet, and
    /// for nothing else.
    #[arg(long, global = true)]
    allow_unsigned_plugins: bool,
}

impl PluginArgs {
    /// Load the plugins these arguments ask for.
    ///
    /// `--no-plugins` short-circuits to an empty registry without touching the
    /// filesystem, so it is also the way out of a plugin directory that will not load
    /// at all.
    ///
    /// # Errors
    ///
    /// Fails if the plugin directory cannot be read, or if a plugin in it is not a
    /// usable component, is not signed by a trusted key, or cannot describe itself. A
    /// plugin that is installed but unusable is a configuration error the user has to
    /// see: skipping it would silently change what pm decides about a build while they
    /// believe the plugin they installed is in play.
    fn load(&self) -> miette::Result<Registry> {
        if self.no_plugins {
            return Ok(Registry::empty());
        }
        let dir = match self.plugin_dir.clone() {
            Some(dir) => dir,
            None => default_plugin_dir()?,
        };
        Loader::new(dir)
            .allow_unsigned(self.allow_unsigned_plugins)
            .load()
    }
}

#[derive(clap::ValueEnum, Clone, Copy, PartialEq, Eq)]
enum ExplainFormat {
    Text,
    Yaml,
}

#[derive(Subcommand)]
enum Commands {
    /// Build and package the project described by a build file.
    ///
    /// The build file is read first: every step command is matched against the
    /// built-in fingerprint table to derive the sandbox policy, and a command
    /// that matches nothing aborts the build before anything runs. Use
    /// `pm explain` to see that policy, and `--permissive` to build anyway.
    Build {
        /// Path to the build file.
        file: PathBuf,
        /// Allow commands that match no built-in fingerprint.
        #[arg(long)]
        permissive: bool,
        /// Run the build steps on the host instead of inside the sandbox.
        ///
        /// For debugging a build that the jail breaks. The build file then runs
        /// with your full privileges and can read your home directory, so only
        /// use it on a build file you wrote yourself.
        #[arg(long)]
        unsandboxed: bool,
        /// How many packages to build at once. Defaults to the core count.
        ///
        /// A dependency graph is built with several packages in flight at a
        /// time. `-j1` builds them one after another, which is the first thing
        /// to reach for when a build fails only under concurrency.
        #[arg(short, long, value_name = "N")]
        jobs: Option<NonZeroUsize>,
    },
    /// Print the sandbox policy derived from a build file, without building.
    ///
    /// Lists every step command, the fingerprint that matched it, the
    /// capabilities those matches add up to, and the digest of the whole thing.
    /// Exits non-zero when a command matches no fingerprint, so it doubles as a
    /// lint in a pre-commit hook or CI.
    Explain {
        /// Path to the build file.
        file: PathBuf,
        /// Report unmatched commands instead of stopping at the first batch.
        ///
        /// The table is printed in full and the exit status is still non-zero.
        #[arg(long)]
        permissive: bool,
        /// Output format; YAML is a versioned interface for automated policy gates.
        #[arg(long, value_enum, default_value_t = ExplainFormat::Text)]
        format: ExplainFormat,
    },
    /// Print where a source URL will be downloaded, without fetching it.
    SourcePath {
        /// The same URL as the recipe's dl_urls key.
        url: Url,
        /// Print a path relative to the build working directory instead of /build.
        #[arg(long)]
        relative: bool,
    },
    /// Convert a Starlark `.package` or YAML build file to a Rhai `.rhai` recipe.
    ///
    /// Recipes are Rhai now; Starlark and YAML are deprecated and still load, with
    /// a warning, until support for them is removed. The new file describes the
    /// same package. It is not signed - run `pm sign` on it - and comments are not
    /// carried over. Starlark is evaluated, so loops and functions come out as the
    /// steps they produced. The old file is left in place.
    Migrate {
        /// The Starlark or YAML build file to convert.
        file: PathBuf,
        /// Where to write the result. Defaults to the input with a `.rhai` extension.
        #[arg(short, long, value_name = "PATH", conflicts_with_all = ["stdout", "recursive"])]
        output: Option<PathBuf>,
        /// Print the result instead of writing it.
        #[arg(long)]
        stdout: bool,
        /// Also convert every Starlark or YAML build file it depends on, and rename
        /// those dependencies.
        ///
        /// Relative dependency paths are resolved against the current directory,
        /// as `pm build` does.
        #[arg(short, long, conflicts_with = "stdout")]
        recursive: bool,
        /// Overwrite files that already exist.
        #[arg(short, long)]
        force: bool,
    },
    /// Write an example build file to the given path.
    ///
    /// A path ending in `.rhai` gets a Rhai recipe. Starlark is deprecated and is
    /// not generated; any other path gets the deprecated YAML form.
    Generate {
        /// Path the example build file is written to.
        file: PathBuf,
        /// Overwrite the file if it already exists.
        #[arg(short, long)]
        force: bool,
    },
    /// Run a binary contained in a built package.
    ///
    /// The package carries a permission profile that was inferred at build time
    /// from its source, its ELF headers and a traced run, and the package itself
    /// says whether that profile is enforced. `--enforce` turns denial on for a
    /// profile nobody has promoted; `--audit` replaces the jailed run with a
    /// traced one that reports what enforcing it would have broken.
    Run {
        /// Path to the .cpkg archive.
        package: PathBuf,
        /// Name of the binary to run; prompts when omitted.
        #[arg(short, long)]
        bin: Option<String>,
        /// Let the program reach the network.
        ///
        /// Off by default: the program runs in its own empty network namespace
        /// and cannot talk to the host, the LAN or the internet.
        #[arg(short, long)]
        network: bool,
        /// Report what the program does outside its profile, and deny nothing.
        ///
        /// Answers "what would enforcing this profile break?", which landlock
        /// cannot: it has no log-only mode and reports no violations, so the only
        /// honest audit is to watch a real execution. The entrypoint runs under
        /// the ptrace monitor and every access outside the profile is reported,
        /// with a summary of the grants a promotion would need.
        ///
        /// THE AUDITED RUN IS NOT JAILED. ptrace observes, it does not deny, and
        /// the monitor execs the entrypoint directly rather than in the
        /// container - so the program runs with your own privileges. Audit only
        /// a package you were already willing to run.
        #[arg(long, conflicts_with = "enforce")]
        audit: bool,
        /// Deny everything outside the profile, even while it is still in audit.
        ///
        /// Attaches the landlock ruleset for a profile that has not been
        /// promoted. A derived profile only describes what was OBSERVED, so this
        /// is how you find out whether promoting it would break the package -
        /// without rewriting the archive or invalidating its signature. If the
        /// program dies on a path nobody watched, run it under `--audit` and
        /// read what it asked for.
        #[arg(long)]
        enforce: bool,
        /// Run a package that ships its own kernel on the host's kernel.
        ///
        /// A package built with `kernel = kernel(image = ...)` normally boots that
        /// kernel in a QEMU virtual machine and runs the program inside it. This
        /// runs it in the usual namespace jail instead, ignoring its kernel. No
        /// effect on a package that ships none.
        #[arg(long)]
        host_kernel: bool,
        /// Boot a package's own kernel by starting qemu-system-x86_64 from PATH
        /// yourself, without asking plugins.
        ///
        /// Normally a plugin that launches machines, such as libvirt, is asked
        /// first and pm starts QEMU itself only when none answers. No effect on a
        /// package that ships no kernel.
        #[arg(long, conflicts_with = "host_kernel")]
        qemu: bool,
    },
    /// Print the permission profile recorded in a package.
    ///
    /// Lists every grant, where it was inferred from, the evidence behind it,
    /// and whether the profile is enforced or merely audited. A profile is
    /// derived by observation and is therefore incomplete by construction, which
    /// is why a fresh one is only ever in audit mode: reading this report is how
    /// you decide whether `pm promote` would be safe.
    Profile {
        /// Path to the .cpkg archive.
        package: PathBuf,
        /// Read the profile without checking who the package came from.
        ///
        /// The profile is data from inside the archive, so an unverified one
        /// says only what its author wants it to say.
        #[arg(long)]
        unsigned: bool,
        /// Trust store to verify the signature against.
        #[arg(long, value_name = "DIR")]
        trust_dir: Option<PathBuf>,
    },
    /// Promote a package's profile from audit to enforcing.
    ///
    /// Nothing else in `pm` ever does this. A profile is inferred from one
    /// traced run plus static analysis, so it describes what the package was
    /// SEEN to need, never what it can need - enforcing it is a human decision,
    /// made after reading `pm profile` and, ideally, a few runs of
    /// `pm run --audit`. Once promoted, landlock denies every path outside the
    /// profile and the package stops working the first time it takes one.
    ///
    /// This rewrites the `metadata` member inside the archive, so every byte the
    /// old signature covered has changed and that signature is void. It is
    /// replaced with a fresh one by default; `--no-sign` keeps your key out of
    /// it and moves the dead signature aside instead.
    Promote {
        /// Path to the .cpkg archive.
        package: PathBuf,
        /// Rewrite the archive without signing it again.
        ///
        /// The old `<PACKAGE>.sig` is renamed to `<PACKAGE>.sig.stale`, because
        /// it cannot verify the rewritten archive and leaving it in place would
        /// only make `pm run` fail with a signature error. Run `pm sign` next.
        #[arg(long)]
        no_sign: bool,
        /// Promote a package that carries no valid signature.
        ///
        /// Without this, a package that has a signature must pass verification
        /// and a package with none is refused. Re-signing an archive you never
        /// verified means vouching, with your own key, for bytes you did not
        /// check.
        #[arg(long)]
        unsigned: bool,
        /// Signing key to use instead of the one under your config directory.
        #[arg(long, value_name = "PATH")]
        key: Option<PathBuf>,
        /// Trust store used to verify the old signature and trust a new key.
        #[arg(long, value_name = "DIR")]
        trust_dir: Option<PathBuf>,
    },
    /// Sign a build file or a package with your key.
    ///
    /// Writes a detached `<FILE>.sig` next to it, so a package travels as two
    /// files. Generates your signing key on first use and trusts it locally,
    /// otherwise you could not verify your own work.
    Sign {
        /// Path to the build file or .cpkg archive to sign.
        file: PathBuf,
        /// Signing key to use instead of the one under your config directory.
        #[arg(long, value_name = "PATH")]
        key: Option<PathBuf>,
        /// Trust store a freshly generated key is added to.
        #[arg(long, value_name = "DIR")]
        trust_dir: Option<PathBuf>,
    },
    /// Create the signing key without signing anything.
    ///
    /// Refuses to overwrite an existing key: a lost signing key cannot be
    /// recovered, and everything signed with it has to be signed again under a
    /// key nobody trusts yet.
    Keygen {
        /// Destroy an existing key and put a new one in its place.
        #[arg(short, long)]
        force: bool,
        /// Write the key here instead of under your config directory.
        #[arg(long, value_name = "PATH")]
        key: Option<PathBuf>,
        /// Trust store the new key is added to.
        #[arg(long, value_name = "DIR")]
        trust_dir: Option<PathBuf>,
    },
    /// List the installed plugins and what each of them may ask for.
    ///
    /// Plugins are WebAssembly components that answer what pm's built-in tables
    /// cannot: what an unrecognised build command needs from the jail, and what a
    /// source file in a language pm has no grammar for implies about the built
    /// program. They run inside pm, so this is the review surface - every line of
    /// it is a claim the plugin makes about itself, which pm then holds it to.
    Plugins {
        /// Also print the SHA-256 of each plugin file and the digest of the set.
        ///
        /// The set digest is what `pm explain` folds into a build policy's own, so
        /// this is how to tell two policy digests apart when the build file has not
        /// changed.
        #[arg(long)]
        digests: bool,
    },
    /// Make, list, start, stop and remove your virtual machines.
    ///
    /// A machine is made from a template - a disk image - and gets a copy-on-write
    /// disk of its own on top of it, so any number of machines share one template's
    /// space. Each has a label, the colour a desktop frames its windows in. They
    /// are yours, kept under `$XDG_DATA_HOME/pm/machines`, and run as you. pm does
    /// none of this itself: the first installed plugin that manages machines, such
    /// as quickemu, decides what to run, and pm runs it.
    Machine {
        #[command(subcommand)]
        command: MachineCommand,
    },
    /// Administer this machine: its services, its updates, and commands run as
    /// root.
    ///
    /// pm's system service does the work, as the `pm` user, after polkit has
    /// asked an administrator to authenticate - through the desktop when one is
    /// running, else on this terminal. This is what sudo, su and run0 were for.
    System {
        #[command(subcommand)]
        command: SystemCommand,
    },
    /// Accept signatures made by a public key from now on.
    ///
    /// Takes the key as hex, or the path to a file holding it - either a `.pub`
    /// from the trust store or any `.sig`, whose signer is then trusted.
    Trust {
        /// Public key hex, or a path to a `.pub` or `.sig` file.
        #[arg(value_name = "PUBKEY_HEX|FILE")]
        key: String,
        /// Trust store to add the key to.
        #[arg(long, value_name = "DIR")]
        trust_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum SystemCommand {
    /// Start a unit; a bare name is a service.
    Start {
        /// The unit, such as `sshd` or `fstrim.timer`.
        unit: String,
    },
    /// Stop a unit.
    Stop {
        /// The unit.
        unit: String,
    },
    /// Stop a unit if it runs, then start it.
    Restart {
        /// The unit.
        unit: String,
    },
    /// Ask a unit to reload its configuration.
    Reload {
        /// The unit.
        unit: String,
    },
    /// Install the newest version of the system, for the next boot.
    Update {
        /// Reboot into it once it is installed. Nothing reboots when there was
        /// nothing newer.
        #[arg(long)]
        reboot: bool,
    },
    /// Run a command as root, or root's shell when none is given.
    ///
    /// The command gets a terminal of its own, which this one is relayed to,
    /// and pm leaves with its exit status.
    Run {
        /// The command and its arguments.
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "COMMAND"
        )]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
enum MachineCommand {
    /// Make a machine from a template, or an empty one that installs a system
    /// from CDs, and leave it stopped.
    ///
    /// The template or CDs are installed first, once: every later machine made
    /// from the same image reuses it. An image is the same only if it has the same
    /// bytes, so a changed image under the same name is installed beside the old
    /// one, and the machines made from the old one keep it.
    Create {
        /// What to call the machine: 1-32 characters of a-z, 0-9 and `-`,
        /// starting with a letter.
        name: String,
        /// The template's disk image, raw or qcow2.
        #[arg(long, value_name = "PATH", required_unless_present = "installer")]
        image: Option<PathBuf>,
        /// What to call the template. Defaults to the image's file name.
        #[arg(long, value_name = "NAME", requires = "image")]
        template_name: Option<String>,
        /// The firmware the template boots with: uefi or bios. A machine that
        /// installs from CDs boots UEFI.
        #[arg(long, default_value = "uefi", conflicts_with = "installer")]
        firmware: Firmware,
        /// A CD to install the machine's system from, instead of a template; the
        /// machine starts with an empty disk and boots the first CD. Give it more
        /// than once for more CDs.
        #[arg(long, value_name = "PATH", conflicts_with = "image")]
        installer: Vec<PathBuf>,
        /// The system the CDs install: linux or windows. The machine is also
        /// given the host's CD of tools for that system, after the others.
        #[arg(long, default_value = "linux", requires = "installer")]
        system: System,
        /// The CD of tools for the system, instead of the host's
        /// `pm/machines/<system>-tools.iso` under one of `$XDG_DATA_DIRS`.
        /// Windows has no virtio drivers of its own and cannot install without
        /// one; a Linux machine without one installs, and shows only its screen.
        #[arg(long, value_name = "PATH", requires = "installer")]
        tools: Option<PathBuf>,
        /// The colour the machine's windows are framed in: red, orange, yellow,
        /// green, gray, blue, purple or black.
        #[arg(long, default_value = "gray")]
        label: Label,
        /// Memory, in MiB. Defaults to 2048, or 4096 for Windows, which is
        /// Windows 11's least.
        #[arg(long, value_name = "MIB")]
        memory: Option<u64>,
        /// Virtual CPUs.
        #[arg(long, value_name = "N", default_value_t = 2)]
        cpus: u32,
        /// The size of the machine's disk, in GiB. Defaults to 32, or 64 for
        /// Windows, which is Windows 11's least. Never smaller than the
        /// template's disk, whatever this says.
        #[arg(long, value_name = "GIB")]
        disk: Option<u64>,
    },
    /// List your machines.
    List,
    /// Start a machine.
    Start {
        /// The machine's name.
        name: String,
    },
    /// Ask a machine to shut down, as its power button would.
    Stop {
        /// The machine's name.
        name: String,
    },
    /// Power a machine off at once, as pulling its plug would.
    Kill {
        /// The machine's name.
        name: String,
    },
    /// Power a machine off and delete it and its disk. Its template stays.
    Remove {
        /// The machine's name.
        name: String,
    },
}

fn main() -> miette::Result<()> {
    // Inside a package's virtual machine this binary is init, and nothing below -
    // logging, argument parsing - applies to it.
    if pm::vm::guest::is_guest_init() {
        pm::vm::guest::run();
    }

    // Logging is initialised before parsing so that argument-parsing failures
    // are logged too, which means `--verbose` has to be read off the raw
    // arguments: clap has not run yet and cannot be asked.
    let progress = if raw_args_ask_for_verbose() {
        Progress::disabled()
    } else {
        Progress::to_terminal()
    };
    // `RUST_LOG` picks what is logged, as in every LosOS program; unset or
    // unparsable, it is `info`, which is what pm always logged.
    fmt()
        .without_time()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(progress.log_sink())
        .init();

    // Destructured rather than matched through `args`, so the plugin flags stay
    // reachable while the subcommand is moved out arm by arm.
    let Arge {
        command,
        verbose: _,
        plugins: plugin_args,
    } = Arge::parse();

    match command {
        Commands::Build {
            file,
            permissive,
            unsandboxed,
            jobs,
        } => build(
            &file,
            permissive,
            unsandboxed,
            jobs,
            &plugin_args.load()?,
            &progress,
        )?,
        Commands::Explain {
            file,
            permissive,
            format,
        } => {
            explain(&file, permissive, format, &plugin_args.load()?)?;
        }
        Commands::SourcePath { url, relative } => {
            let path = Step::download_path(&url)?;
            let path = if relative {
                path
            } else {
                Path::new(CONTAINER_WORKDIR).join(path)
            };
            println!("{}", path.display());
        }
        Commands::Plugins { digests } => list_plugins(&plugin_args.load()?, digests)?,
        Commands::Generate { file, force } => generate(&file, force)?,
        Commands::Migrate {
            file,
            output,
            stdout,
            recursive,
            force,
        } => migrate_command(&file, output.as_deref(), stdout, recursive, force)?,
        Commands::Run {
            package,
            bin,
            network,
            audit,
            enforce,
            host_kernel,
            qemu,
        } => {
            if !package.exists() {
                return Err(miette!("The path {} does not exist.", package.display()));
            }
            if network {
                warn!(
                    "--network was given: the program shares the host network namespace \
                     and can reach the internet, the LAN and host-local services"
                );
            }
            if audit {
                warn!(
                    "--audit was given: the entrypoint is TRACED, not jailed. ptrace observes \
                     and denies nothing, so the program runs with your privileges for the \
                     length of the audit. Only audit a package you were already willing to run."
                );
            }
            if enforce {
                info!(
                    "--enforce was given: the recorded profile is applied even though nobody \
                     promoted it, so this run denies what a promoted package would deny"
                );
            }
            // `PackageRunner::run` owns the `Workspace` and `SandboxedChild` guards for
            // the whole lifetime of the sandboxed process, and both are dropped before it
            // hands back an `ExitStatus`. This frame therefore holds nothing that
            // implements `Drop`, which is what makes the `std::process::exit` below safe:
            // that call terminates immediately and runs no destructors, so were a guard
            // still live here it would leak the staging directory and leave the child
            // unreaped. Do not move the exit into a scope that still holds one.
            // Scoped so the runner - and the `PathBuf` it owns - is gone before
            // the `exit` below, keeping the claim above literally true.
            let status = {
                let mut runner = PackageRunner::new(package);
                runner
                    .allow_network(network)
                    .audit(audit)
                    .enforce(enforce)
                    .host_kernel(host_kernel);
                if !qemu {
                    runner.launcher(Box::new(PluginLauncher(plugin_args.clone())));
                }
                runner.run(bin)?
            };
            if !status.success() {
                warn!(
                    code = status.code,
                    reason = %status.reason,
                    "sandboxed program exited unsuccessfully"
                );
                std::process::exit(status.code);
            }
        }
        Commands::Sign {
            file,
            key,
            trust_dir,
        } => sign(&file, key, trust_dir)?,
        Commands::Keygen {
            force,
            key,
            trust_dir,
        } => keygen(force, key, trust_dir)?,
        Commands::Profile {
            package,
            unsigned,
            trust_dir,
        } => profile(&package, unsigned, trust_dir)?,
        Commands::Promote {
            package,
            no_sign,
            unsigned,
            key,
            trust_dir,
        } => promote(&package, no_sign, unsigned, key, trust_dir)?,
        Commands::Trust { key, trust_dir } => trust(&key, trust_dir)?,
        Commands::Machine { command } => machine(command, &plugin_args.load()?)?,
        Commands::System { command } => match command {
            SystemCommand::Start { unit } => pm::system::client::manage(Verb::Start, &unit)?,
            SystemCommand::Stop { unit } => pm::system::client::manage(Verb::Stop, &unit)?,
            SystemCommand::Restart { unit } => pm::system::client::manage(Verb::Restart, &unit)?,
            SystemCommand::Reload { unit } => pm::system::client::manage(Verb::Reload, &unit)?,
            SystemCommand::Update { reboot } => pm::system::client::update(reboot)?,
            // No guard is live in this frame, so leaving with the command's
            // status skips nothing that needed dropping.
            SystemCommand::Run { command } => std::process::exit(pm::system::client::run(command)?),
        },
    }

    Ok(())
}

/// Carries out a `pm machine` subcommand through the plugin that manages machines.
///
/// # Errors
///
/// A name is not usable, the image cannot be read, no plugin manages machines, or a
/// step failed.
fn machine(command: MachineCommand, plugins: &Registry) -> miette::Result<()> {
    let request = match command {
        MachineCommand::Create {
            name,
            image,
            template_name,
            firmware,
            installer,
            system,
            tools,
            label,
            memory,
            cpus,
            disk,
        } => {
            check_machine_name(&name)?;
            let windows = !installer.is_empty() && system == System::Windows;
            let memory = memory.unwrap_or(if windows { 4096 } else { 2048 });
            let disk = disk.unwrap_or(if windows { 64 } else { 32 });
            if memory == 0 || cpus == 0 {
                return Err(miette!("a machine needs some memory and at least one CPU"));
            }
            let disk_size = disk
                .checked_mul(1 << 30)
                .ok_or_else(|| miette!("{disk} GiB is more disk than there is"))?;
            let (source, disk_size) = match image {
                Some(image) => {
                    let template =
                        Template::from_image(&image, template_name.as_deref(), firmware)?;
                    let disk_size = disk_size.max(template.disk_size);
                    (Source::Template(template), disk_size)
                }
                None => {
                    let tools = tools.or_else(|| guest_tools(system));
                    if windows && tools.is_none() {
                        return Err(miette!(
                            help = "pass the CD with --tools, or install the package that \
                                    puts one there",
                            "Windows Setup needs a CD of virtio drivers, and there is none at \
                             {} under $XDG_DATA_DIRS",
                            guest_tools_path(system)
                        ));
                    }
                    let media = installer
                        .iter()
                        .chain(&tools)
                        .map(|cd| Media::from_image(cd))
                        .collect::<miette::Result<Vec<_>>>()?;
                    (Source::Installer { system, media }, disk_size)
                }
            };
            MachineRequest::Create(Spec {
                name,
                label,
                source,
                disk_size,
                memory_mib: memory,
                cpus,
                kvm: host_has_kvm(),
                arch: std::env::consts::ARCH.to_owned(),
            })
        }
        MachineCommand::List => MachineRequest::List,
        MachineCommand::Start { name } => MachineRequest::Start(checked(name)?),
        MachineCommand::Stop { name } => MachineRequest::Stop(checked(name)?),
        MachineCommand::Kill { name } => MachineRequest::Kill(checked(name)?),
        MachineCommand::Remove { name } => MachineRequest::Remove(checked(name)?),
    };
    carry_out(plugins, &request)
}

/// `name`, if it can name a machine. Checked before a plugin sees it, so that no
/// plugin has to be trusted to quote it.
fn checked(name: String) -> miette::Result<String> {
    check_machine_name(&name)?;
    Ok(name)
}

/// Derives the policy from `file`, then builds and packages it.
///
/// # Errors
///
/// Fails if the build file is missing or unparseable, if a command matches no
/// fingerprint and `permissive` is false, or if the build itself fails.
fn build(
    file: &Path,
    permissive: bool,
    unsandboxed: bool,
    jobs: Option<NonZeroUsize>,
    plugins: &Registry,
    progress: &Progress,
) -> miette::Result<()> {
    if !file.exists() {
        return Err(miette!("The path {} does not exist.", file.display()));
    }

    let mut build_file = BuildFile::load_with(file, plugins)?;
    // The graph expands every package again as it resolves it; this copy exists so the
    // policy logged below is the one the top-level package will actually build under.
    build_file.expand(plugins)?;
    let policy =
        BuildPolicy::derive_with(&build_file, permissive, plugins).wrap_err_with(|| {
            format!(
                "cannot derive a sandbox policy for {}; run `pm explain {}` to see the whole \
             build file, or pass --permissive to build it anyway",
                file.display(),
                file.display()
            )
        })?;
    info!(
        fingerprint = policy.fingerprint(),
        capabilities = ?policy.capabilities(),
        "derived the sandbox policy from the build file"
    );

    if unsandboxed {
        warn!(
            file = %file.display(),
            "--unsandboxed was given: build steps run on the host with your privileges, \
             outside the jail. A hostile build file can read your SSH keys and write \
             anywhere you can. Use this only to debug a build file you trust."
        );
    }

    let archive = run_build(
        &build_file,
        BuildOptions {
            permissive,
            unsandboxed,
            jobs,
            plugins,
        },
        progress,
    )?;
    info!(archive = %archive.display(), "packaged");
    Ok(())
}

/// Asks the installed plugins to start a package's kernel, loading them only then.
///
/// `pm run` of a package with no kernel, or one run with `--host-kernel`, never boots
/// a machine, so it should not pay for compiling every plugin or fail on a plugin
/// directory it had no use for.
struct PluginLauncher(PluginArgs);

impl pm::vm::Launcher for PluginLauncher {
    fn launch(&self, machine: &pm::vm::Machine<'_>) -> miette::Result<Option<pm::vm::Launch>> {
        self.0.load()?.launch(machine)
    }
}

/// Prints the installed plugins, one block each.
///
/// Everything printed is the plugin's own claim about itself, made once at load and
/// held to from then on: the ceiling bounds what its verdicts may ask for, and the
/// extensions decide which files it is shown. Reading this is meant to be a cheap
/// substitute for reading the plugin - which is only worth anything because a plugin
/// had to be signed by a trusted key to be loaded at all.
///
/// Goes to stdout because it is this subcommand's primary output, like `pm explain`'s
/// table and `pm profile`'s report.
///
/// # Errors
///
/// Infallible today; the signature keeps `main`'s dispatch uniform and leaves room for
/// a future `pm plugins` that has to go and look at something.
fn list_plugins(plugins: &Registry, digests: bool) -> miette::Result<()> {
    if plugins.is_empty() {
        println!("No plugins are loaded.");
        println!();
        println!(
            "pm looks for WebAssembly components in {}. See plugins/README.md for what \
             one is and how to build it.",
            default_plugin_dir().map_or_else(
                |_| "<config>/pm/plugins".to_owned(),
                |dir| dir.display().to_string()
            )
        );
        return Ok(());
    }

    println!("{:<LABEL_WIDTH$}{}", "plugins:", plugins.len());
    if digests {
        println!("{:<LABEL_WIDTH$}{}", "set digest:", plugins.digest());
    }

    for plugin in plugins.plugins() {
        let manifest = plugin.manifest();
        println!();
        println!(
            "{} {} ({})",
            manifest.name,
            manifest.version,
            plugin.trust()
        );
        if plugin.trust() == Trust::Unverified {
            println!(
                "{:<LABEL_WIDTH$}loaded without a signature check",
                "WARNING:"
            );
        }
        println!("{:<LABEL_WIDTH$}{}", "summary:", manifest.summary);
        println!(
            "{:<LABEL_WIDTH$}{}",
            "hooks:",
            join_or_none(manifest.hooks.iter().map(ToString::to_string))
        );
        // Only meaningful for the hook it bounds, and `Manifest` already empties it for
        // a plugin that does not classify - so an empty ceiling here means "will never
        // grant anything", which is worth saying out loud.
        if manifest.hooks.contains(&pm::plugin::Hook::ClassifyCommand) {
            println!(
                "{:<LABEL_WIDTH$}{}",
                "grants:",
                join_or_none(
                    manifest
                        .grants_at_most
                        .iter()
                        .map(|capability| format!("{capability:?}"))
                )
            );
        }
        if manifest.hooks.contains(&pm::plugin::Hook::ScanSource) {
            println!(
                "{:<LABEL_WIDTH$}{}",
                "scans:",
                join_or_none(
                    manifest
                        .source_extensions
                        .iter()
                        .map(|ext| format!(".{ext}"))
                )
            );
        }
        if !manifest.symbols.is_empty() {
            println!("{:<LABEL_WIDTH$}{}", "symbols:", manifest.symbols.len());
            for symbol in manifest.symbols.values() {
                let summary = if symbol.summary.is_empty() {
                    String::new()
                } else {
                    format!("  ({})", symbol.summary)
                };
                println!(
                    "  %{{{}:{}}} = {}{summary}",
                    manifest.name, symbol.name, symbol.value
                );
            }
        }
        if !manifest.recipe_functions.is_empty() {
            println!(
                "{:<LABEL_WIDTH$}{}",
                "recipes:",
                manifest.recipe_functions.len()
            );
            let namespace = manifest.name.replace('-', "_");
            for function in manifest.recipe_functions.values() {
                let summary = function.doc.lines().next().unwrap_or_default();
                let summary = if summary.is_empty() {
                    String::new()
                } else {
                    format!("  ({summary})")
                };
                println!(
                    "  {namespace}::{}({}) -> {}{summary}",
                    function.name,
                    function.params.join(", "),
                    function.returns.label()
                );
            }
        }
        if !manifest.launchers.is_empty() {
            println!(
                "{:<LABEL_WIDTH$}{}",
                "launchers:",
                comma_join(manifest.launchers.iter().cloned())
            );
        }
        if manifest.manages_machines {
            println!("{:<LABEL_WIDTH$}yes", "machines:");
        }
        println!("{:<LABEL_WIDTH$}{}", "file:", plugin.path().display());
        if digests {
            println!("{:<LABEL_WIDTH$}{}", "sha256:", plugin.sha256());
        }
    }
    Ok(())
}

/// Comma-join `items`, or `none` when there are none.
///
/// An empty list is printed rather than omitted for the same reason
/// [`pm::perms::Permissions::report`] prints its empty groups: the absence of a grant is
/// the interesting half of a review, and an omitted line reads as an oversight.
fn join_or_none(items: impl Iterator<Item = String>) -> String {
    let joined = comma_join(items);
    if joined.is_empty() {
        "none".to_owned()
    } else {
        joined
    }
}

/// Whether the raw command line asks for verbose output.
///
/// Scanned rather than parsed because logging is set up before clap runs; the
/// flag is also declared on [`Arge`] so `--help` documents it and clap accepts
/// it wherever it appears.
fn raw_args_ask_for_verbose() -> bool {
    std::env::args().any(|arg| arg == "-v" || arg == "--verbose")
}

/// The single seam between the CLI and the builder.
///
/// The caller's flags reach [`BuildFile::run_with_progress`] as a
/// [`BuildOptions`], rather than the [`BuildOptions::default`] that
/// [`BuildFile::run`] and [`BuildFile::run_with`] would supply - the safe answer
/// to both, and therefore not the one the caller asked for.
///
/// No policy is handed over. The recursive dependency walk derives one per
/// package from that package's own build file, so the policy the caller already
/// has in hand describes the top-level package and nothing below it.
///
/// `options` applies to every package built out of this one, which is
/// [`BuildFile::run_with`]'s contract: a permissive top-level build does not get
/// to impose strict classification on its dependencies, and an unsandboxed one
/// has already given up the jail.
///
/// # Errors
///
/// Propagates whatever the build fails with.
fn run_build(
    build_file: &BuildFile,
    options: BuildOptions<'_>,
    progress: &Progress,
) -> miette::Result<PathBuf> {
    build_file.run_with_progress(options, progress)
}

/// Prints the policy derived from `file` without building it.
///
/// The table goes to stdout because it is this subcommand's primary output and
/// is meant to be read, piped and diffed; everything else stays on `tracing`.
///
/// # Errors
///
/// Fails if the build file is missing or unparseable, and - after printing the
/// whole table - if any command matched no fingerprint, so that the subcommand
/// works as a lint.
fn explain(
    file: &Path,
    permissive: bool,
    format: ExplainFormat,
    plugins: &Registry,
) -> miette::Result<()> {
    if !file.exists() {
        return Err(miette!("The path {} does not exist.", file.display()));
    }

    let mut build_file = BuildFile::load_with(file, plugins)?;
    // Expanded first, so the table below prints the commands that would run rather than
    // the ones the file was written with. Which symbols did that is printed too.
    let symbols = build_file.expand(plugins)?;
    let policy =
        BuildPolicy::derive_with(&build_file, permissive, plugins).wrap_err_with(|| {
            format!(
                "cannot derive a sandbox policy for {}; pass --permissive to list every \
             command anyway",
                file.display()
            )
        })?;

    if format == ExplainFormat::Yaml {
        explain_yaml(&build_file, &policy, &symbols, plugins)?;
    } else {
        explain_text(file, &build_file, &policy, &symbols, plugins);
    }

    let unmatched = policy
        .matches()
        .iter()
        .filter(|(_, fingerprint)| *fingerprint == UNMATCHED)
        .count();
    if unmatched > 0 {
        return Err(miette!(
            help = "A command needs a fingerprint before the sandbox can grant it \
                    anything. Rewrite it to use a program the table knows, or run \
                    `pm build --permissive` and accept that those commands get no \
                    capabilities at all.",
            "{unmatched} {} in {} {} no built-in fingerprint.",
            if unmatched == 1 {
                "command"
            } else {
                "commands"
            },
            file.display(),
            if unmatched == 1 { "matches" } else { "match" }
        ));
    }

    Ok(())
}

fn explain_text(
    file: &Path,
    build_file: &BuildFile,
    policy: &BuildPolicy,
    symbols: &std::collections::BTreeSet<String>,
    plugins: &Registry,
) {
    let capabilities = if policy.capabilities().is_empty() {
        "none".to_owned()
    } else {
        comma_join(
            policy
                .capabilities()
                .iter()
                .map(|capability| format!("{capability:?}")),
        )
    };

    println!("{:<LABEL_WIDTH$}{}", "build file:", file.display());
    println!(
        "{:<LABEL_WIDTH$}{} {}",
        "package:",
        build_file.name(),
        build_file.version_string()
    );
    println!("{:<LABEL_WIDTH$}{}", "digest:", policy.fingerprint());
    println!("{:<LABEL_WIDTH$}{capabilities}", "grants:");
    // Only when there are any. The digest above is mixed with the plugin set exactly
    // when it is non-empty, so printing "plugins: none" would invite the reading that
    // the digest still depends on it.
    if !plugins.is_empty() {
        println!(
            "{:<LABEL_WIDTH$}{}",
            "plugins:",
            comma_join(plugins.plugins().iter().map(|plugin| format!(
                "{} {}",
                plugin.manifest().name,
                plugin.manifest().version
            )))
        );
    }
    if !symbols.is_empty() {
        println!();
        println!("{:<SYMBOL_WIDTH$}VALUE", "SYMBOL");
        for reference in symbols {
            // Every reference in the set resolved, or `expand` would have failed, so a
            // plugin that no longer offers one is not a case that can arrive here.
            let value = reference
                .split_once(':')
                .and_then(|(plugin, name)| plugins.symbol(plugin, name))
                .map_or("", |symbol| symbol.value.as_str());
            println!("{reference:<SYMBOL_WIDTH$}{value}");
        }
    }
    println!();

    if policy.matches().is_empty() {
        println!("This build file runs no commands.");
        return;
    }

    // Fold rather than `max()` so there is no `Option` to unwrap, and start
    // from the header so a table of short commands still lines up under it.
    let width = policy
        .matches()
        .iter()
        .fold(COMMAND_HEADER.len(), |widest, (command, _)| {
            widest.max(command.chars().count())
        })
        .min(COMMAND_WIDTH_CAP);

    println!("{COMMAND_HEADER:<width$}  FINGERPRINT");
    for (command, fingerprint) in policy.matches() {
        println!("{command:<width$}  {fingerprint}");
    }

    if policy.matches().iter().any(|(_, name)| *name == UNMATCHED) {
        println!();
    }
}

/// Versioned, deterministic data for recipe generators and policy gates. Do not
/// serialise private implementation structs: their layout is not a CLI contract.
#[derive(Serialize)]
struct ExplainReport<'a> {
    schema_version: u8,
    name: &'a str,
    version: &'a [String],
    dependencies: Vec<&'a Path>,
    fingerprint: &'a str,
    capabilities: &'a [Capability],
    commands: Vec<ExplainedCommand<'a>>,
    plugins: Vec<ExplainedPlugin<'a>>,
    symbols: std::collections::BTreeMap<&'a str, &'a str>,
    downloads: Vec<ExplainedDownload<'a>>,
}

#[derive(Serialize)]
struct ExplainedCommand<'a> {
    command: &'a str,
    fingerprint: &'a str,
    matched: bool,
}

#[derive(Serialize)]
struct ExplainedPlugin<'a> {
    name: &'a str,
    version: &'a str,
    sha256: &'a str,
    trust: String,
}

#[derive(Serialize)]
struct ExplainedDownload<'a> {
    step: &'a str,
    url: &'a Url,
    sha256: &'a str,
    path: PathBuf,
}

fn explain_yaml(
    build_file: &BuildFile,
    policy: &BuildPolicy,
    symbols: &std::collections::BTreeSet<String>,
    plugins: &Registry,
) -> miette::Result<()> {
    let mut downloads = Vec::new();
    for step in build_file.steps() {
        if let Some(urls) = &step.dl_urls {
            let mut urls: Vec<_> = urls.iter().collect();
            urls.sort_unstable_by(|(a, _), (b, _)| a.as_str().cmp(b.as_str()));
            for (url, sha256) in urls {
                downloads.push(ExplainedDownload {
                    step: &step.name,
                    url,
                    sha256,
                    path: Path::new(CONTAINER_WORKDIR).join(Step::download_path(url)?),
                });
            }
        }
    }
    let report = ExplainReport {
        schema_version: 1,
        name: build_file.name(),
        version: build_file.version(),
        dependencies: build_file.dependencies().collect(),
        fingerprint: policy.fingerprint(),
        capabilities: policy.capabilities(),
        commands: policy
            .matches()
            .iter()
            .map(|(command, fingerprint)| ExplainedCommand {
                command,
                fingerprint,
                matched: *fingerprint != UNMATCHED,
            })
            .collect(),
        plugins: plugins
            .plugins()
            .iter()
            .map(|plugin| ExplainedPlugin {
                name: &plugin.manifest().name,
                version: &plugin.manifest().version,
                sha256: plugin.sha256(),
                trust: plugin.trust().to_string(),
            })
            .collect(),
        symbols: symbols
            .iter()
            .filter_map(|reference| {
                let (plugin, name) = reference.split_once(':')?;
                Some((
                    reference.as_str(),
                    plugins.symbol(plugin, name)?.value.as_str(),
                ))
            })
            .collect(),
        downloads,
    };
    print!("{}", to_string(&report).into_diagnostic()?);
    Ok(())
}

/// Prints the permission profile recorded in `package`.
///
/// The report goes to stdout because it is this subcommand's entire output and is
/// meant to be read, piped and diffed; everything else stays on `tracing`. The
/// archive is unpacked into a throwaway workspace to get at it, exactly as
/// `pm run` does, because the profile lives in the `metadata` member.
///
/// # Errors
///
/// Fails if the package does not exist, if its signature is missing, wrong or
/// untrusted and `unsigned` is false, if the staging workspace cannot be
/// created, if `tar` cannot extract the archive, or if the `metadata` member is
/// missing or is not valid YAML.
fn profile(package: &Path, unsigned: bool, trust_dir: Option<PathBuf>) -> miette::Result<()> {
    if !package.exists() {
        return Err(miette!("The path {} does not exist.", package.display()));
    }
    verify_package(package, unsigned, trust_dir.as_deref())?;

    let workspace = Workspace::new("profile")?;
    extract(package, workspace.path())?;
    let (_, metadata) = package_metadata(package, workspace.path())?;

    let recorded = metadata.recorded_permissions();
    let permissions = metadata.permissions();
    let enforcement = metadata.enforcement();

    println!("{:<LABEL_WIDTH$}{}", "archive:", package.display());
    println!(
        "{:<LABEL_WIDTH$}{} {}",
        "package:",
        metadata.name(),
        metadata.version().join(".")
    );
    println!(
        "{:<LABEL_WIDTH$}{enforcement} - {}",
        "mode:",
        describe_mode(enforcement)
    );
    println!();
    println!("{}", permissions.report().trim_end());
    println!();

    // "No profile was recorded" and "a profile was derived and wanted nothing" read
    // identically in the report above - both are an empty grant list - and they call
    // for opposite reactions, so say which one this is.
    if recorded.is_none() {
        println!(
            "This package records NO profile: it predates the field entirely. Nothing was\n\
             inferred for it and nothing was promised about it, so enforcing it would leave\n\
             it only what the runner allows unconditionally - its own files and the dynamic\n\
             loader. Rebuild it rather than promoting it."
        );
        return Ok(());
    }
    if permissions.is_empty() {
        println!(
            "A profile was derived for this package and it came back empty: nothing in the\n\
             source, the ELF headers or the traced run asked for anything outside the package\n\
             itself. Run `pm run --audit {}` over real work before you believe that.",
            package.display()
        );
        return Ok(());
    }

    match enforcement {
        Enforcement::Audit => println!(
            "Nothing here is denied yet, and that is deliberate: this profile was derived by\n\
             watching ONE execution and reading the source, so it knows what the package was\n\
             seen to need, not what it can need. Run `pm run --audit {}` over the work you\n\
             actually expect of it, and promote it with `pm promote {}` once the audit stops\n\
             turning up anything new. `pm run --enforce {}` tries the strict ruleset for a\n\
             single run without rewriting the archive.",
            package.display(),
            package.display(),
            package.display()
        ),
        Enforcement::Enforce => println!(
            "Every access outside this list is denied. If the package dies on a path that\n\
             belongs here, rebuild it so the grant is inferred with evidence behind it; a\n\
             profile is not meant to be edited by hand."
        ),
    }
    Ok(())
}

/// What an enforcement mode actually does to a running package, in one line.
fn describe_mode(enforcement: Enforcement) -> &'static str {
    match enforcement {
        Enforcement::Audit => "accesses outside the profile are reported, none are denied",
        Enforcement::Enforce => "landlock denies every access outside the profile",
    }
}

/// Rewrites `package` so its profile is enforced, and deals with the signature
/// that the rewrite invalidates.
///
/// Promotion changes the `metadata` member, so every byte the detached signature
/// covered has moved and that signature can never verify again. The package is
/// therefore re-signed with your key by default and the substitution is logged;
/// `no_sign` skips that and moves the dead signature aside instead. Neither path
/// leaves a signature that silently fails to match its archive.
///
/// # Errors
///
/// Fails if the package does not exist, if its signature is missing, wrong or
/// untrusted and `unsigned` is false, if the staging workspace cannot be
/// created, if `tar` cannot extract or repack the archive, if the `metadata`
/// member is missing, unparseable or not a YAML mapping, if the promoted archive
/// cannot replace the original, or if the signing key cannot be loaded, created
/// or trusted.
fn promote(
    package: &Path,
    no_sign: bool,
    unsigned: bool,
    key: Option<PathBuf>,
    trust_dir: Option<PathBuf>,
) -> miette::Result<()> {
    if !package.exists() {
        return Err(miette!("The path {} does not exist.", package.display()));
    }

    let signature = sibling(package, SIGNATURE_SUFFIX);
    // Read before anything is rewritten: afterwards the file has been replaced or
    // renamed, and who signed the package before is the one fact worth carrying
    // into the log line that says it no longer does.
    let signer = previous_signer(&signature);
    verify_package(package, unsigned, trust_dir.as_deref())?;

    let workspace = Workspace::new("promote")?;
    extract(package, workspace.path())?;
    let (original, mut metadata) = package_metadata(package, workspace.path())?;

    if metadata.enforcement() == Enforcement::Enforce {
        info!(
            package = %package.display(),
            "the profile is already enforced; leaving the archive and its signature alone"
        );
        return Ok(());
    }

    let grants = metadata.permissions().len();
    if grants == 0 {
        warn!(
            package = %package.display(),
            "promoting a profile with no grants: the package is left with nothing but the \
             runner's unconditional allowances, and everything else it touches is denied"
        );
    }

    // One-way by construction, and the only thing in the tree that moves a
    // profile out of audit. It warns by itself when the package recorded no
    // profile at all.
    metadata.promote();
    write(
        workspace.path().join(METADATA_MEMBER),
        rewrite_metadata(&original, &metadata)?,
    )
    .into_diagnostic()
    .wrap_err("cannot write the promoted package metadata")?;

    // Built beside the package and renamed over it, so a `tar` that fails
    // part-way leaves the original archive intact instead of truncated.
    let staged = sibling(package, PROMOTED_SUFFIX);
    repack(workspace.path(), &staged)?;
    if let Err(source) = rename(&staged, package) {
        let _ = remove_file(&staged);
        return Err(source).into_diagnostic().wrap_err_with(|| {
            format!(
                "cannot replace {} with the promoted archive",
                package.display()
            )
        });
    }
    warn!(
        package = %package.display(),
        grants,
        "profile promoted to enforcing; the archive was rewritten, so its old signature is void"
    );

    if no_sign {
        return retire_signature(&signature, package, signer.as_deref());
    }
    resign(package, key, trust_dir, signer.as_deref())
}

/// The public key of the detached signature at `path`, if one can be read.
///
/// Best effort by design: the answer only names a key in a log line, and a
/// signature that cannot be read at all is what [`verify_package`] reports on.
fn previous_signer(path: &Path) -> Option<String> {
    let text = read_to_string(path).ok()?;
    Signature::from_yaml(&text)
        .ok()
        .map(|signature| signature.public_key_hex().to_owned())
}

/// Moves the signature that promotion invalidated out of the way.
///
/// Renamed rather than deleted: it can never verify the rewritten archive, but it
/// is still the record of who signed the package before. Leaving it under its own
/// name would be worse than either - `pm run` would refuse the package with a
/// signature error that says nothing about the promotion that caused it.
///
/// # Errors
///
/// Fails if the signature exists but cannot be renamed.
fn retire_signature(signature: &Path, package: &Path, signer: Option<&str>) -> miette::Result<()> {
    if !signature.exists() {
        warn!(
            package = %package.display(),
            "the promoted package carries no signature; sign it with `pm sign` before it travels"
        );
        return Ok(());
    }

    let stale = sibling(package, STALE_SIGNATURE_SUFFIX);
    rename(signature, &stale)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "cannot move the invalidated signature {} aside",
                signature.display()
            )
        })?;
    warn!(
        stale = %stale.display(),
        signer = signer.unwrap_or("unknown"),
        "the old signature cannot verify the promoted archive and was moved aside; run `pm sign {}`",
        package.display()
    );
    Ok(())
}

/// Signs the promoted archive, generating and trusting the key on first use.
///
/// Says loudly when the package used to be signed by somebody else: re-signing is
/// the point of the default path, but swapping another signer out for yourself is
/// not something to discover later.
///
/// # Errors
///
/// Fails if the key path cannot be resolved, if the key cannot be loaded or
/// created, if a freshly generated key cannot be trusted, or if the signature
/// cannot be written.
fn resign(
    package: &Path,
    key: Option<PathBuf>,
    trust_dir: Option<PathBuf>,
    previous: Option<&str>,
) -> miette::Result<()> {
    let key_path = resolve_key_path(key)?;
    // Asked before loading, because `load_or_create` erases the difference.
    let generated = !key_path.exists();

    let signing_key = SigningKey::load_or_create(&key_path)?;
    let public_key = signing_key.public_key_hex();

    if generated {
        let dir = resolve_trust_dir(trust_dir)?;
        TrustStore::load(&dir)?.add(&public_key, &dir)?;
        warn!(
            path = %key_path.display(),
            "generated a new signing key and trusted it locally; back it up, it cannot be recovered"
        );
    }

    let written = sign_file(package, &signing_key)?;
    match previous {
        Some(old) if old != public_key => warn!(
            signature = %written.display(),
            previous_signer = old,
            signer = %public_key,
            "re-signed the promoted package with YOUR key; it no longer carries the signature it arrived with"
        ),
        _ => info!(
            signature = %written.display(),
            signer = %public_key,
            "re-signed the promoted package"
        ),
    }
    Ok(())
}

/// Verifies `<package>.sig` against the trust store, or says loudly that it was
/// told not to.
///
/// The same rule `PackageRunner` applies before it unpacks anything: `pm profile`
/// and `pm promote` read metadata that whoever built the package wrote, so an
/// unverified archive is an archive whose profile says whatever its author wants.
///
/// # Errors
///
/// Fails if the trust store cannot be located or read, or if the signature is
/// missing, malformed, wrong, or from an untrusted key.
fn verify_package(package: &Path, unsigned: bool, trust_dir: Option<&Path>) -> miette::Result<()> {
    if unsigned {
        warn!(
            package = %package.display(),
            "signature verification DISABLED; this profile is of unverified origin"
        );
        return Ok(());
    }

    let dir = match trust_dir {
        Some(dir) => dir.to_path_buf(),
        None => default_trust_dir()?,
    };
    let trust = TrustStore::load(&dir)?;
    verify_file(package, &trust).wrap_err_with(|| {
        format!(
            "refusing to open {}: its signature does not check out",
            package.display()
        )
    })
}

/// Reads and parses the `metadata` member of an already-extracted package.
///
/// Hands back the raw YAML alongside the parsed value because `pm promote` writes
/// the file again: the build splices keys into that mapping which [`Metadata`]
/// has no field for - the policy fingerprint, today - and re-rendering a parsed
/// [`Metadata`] would drop every one of them. The text is the only record.
///
/// # Errors
///
/// Fails if the member is missing or unreadable, or is not valid YAML.
fn package_metadata(package: &Path, root: &Path) -> miette::Result<(String, Metadata)> {
    let path = root.join(METADATA_MEMBER);
    let text = read_to_string(&path).into_diagnostic().wrap_err_with(|| {
        format!(
            "{} has no `{METADATA_MEMBER}` member; it is not a pm package",
            package.display()
        )
    })?;
    let metadata = from_str(&text)
        .into_diagnostic()
        .wrap_err_with(|| format!("cannot parse the metadata of {}", package.display()))?;
    Ok((text, metadata))
}

/// Renders `metadata` back into `original`, overwriting only the keys it owns.
///
/// A blind `to_string(&metadata)` would silently drop whatever the build spliced
/// in beside the struct's fields, so the original mapping is the base and the
/// re-serialised struct is layered on top of it.
///
/// # Errors
///
/// Fails if either side does not serialise to a YAML mapping, or if the result
/// cannot be rendered.
fn rewrite_metadata(original: &str, metadata: &Metadata) -> miette::Result<String> {
    let mut merged: Value = from_str(original)
        .into_diagnostic()
        .wrap_err("cannot re-read the package metadata")?;
    let updated = to_value(metadata)
        .into_diagnostic()
        .wrap_err("cannot serialise the promoted metadata")?;

    let (Some(target), Some(source)) = (merged.as_mapping_mut(), updated.as_mapping()) else {
        return Err(miette!("package metadata is not a YAML mapping"));
    };
    for (key, value) in source {
        target.insert(key.clone(), value.clone());
    }

    to_string(&merged)
        .into_diagnostic()
        .wrap_err("cannot render the promoted metadata")
}

/// Extracts `package` into `dest`, preserving permissions, as `pm run` does.
///
/// # Errors
///
/// Fails if `tar` cannot be spawned, or exits unsuccessfully - in which case its
/// status and stderr are reported.
fn extract(package: &Path, dest: &Path) -> miette::Result<()> {
    let output = Command::new("tar")
        .arg("-xpf")
        .arg(package)
        .arg("-C")
        .arg(dest)
        .output()
        .into_diagnostic()
        .wrap_err("cannot run tar")?;

    if !output.status.success() {
        return Err(miette!(
            "tar failed to extract {} into {} ({}): {}",
            package.display(),
            dest.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// Packs `root` into `archive` the way `pm build` does.
///
/// `tar -cJf <archive> -C <root> .`, so a promoted package has the same shape as
/// a freshly built one and `tar -xpf` still puts `metadata` at the package root.
/// Getting this wrong would produce an archive that only fails at run time.
///
/// # Errors
///
/// Fails if `tar` cannot be spawned, or exits unsuccessfully - in which case its
/// status and stderr are reported.
fn repack(root: &Path, archive: &Path) -> miette::Result<()> {
    let output = Command::new("tar")
        .arg("-cJf")
        .arg(archive)
        .arg("-C")
        .arg(root)
        .arg(".")
        .output()
        .into_diagnostic()
        .wrap_err("cannot run tar")?;

    if !output.status.success() {
        return Err(miette!(
            "tar failed to pack {} from {} ({}): {}",
            archive.display(),
            root.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// `<path><suffix>`, appending to the full file name rather than replacing the
/// extension: a package is `foo-1.0.cpkg`, and `Path::with_extension` would eat
/// the `.cpkg`.
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(suffix);
    PathBuf::from(name)
}

/// `pm migrate`: convert Starlark and YAML build files to Rhai and report what to do next.
///
/// # Errors
///
/// Fails if a file cannot be read or converted, or if a target exists and
/// `force` is false.
fn migrate_command(
    file: &Path,
    output: Option<&Path>,
    stdout: bool,
    recursive: bool,
    force: bool,
) -> miette::Result<()> {
    let converted = migrate::convert_file(file, recursive)?;
    if stdout {
        for item in &converted {
            print!("{}", item.text);
        }
        return Ok(());
    }
    // Check every target before writing any, so a refusal halfway through does
    // not leave a half-migrated tree.
    if !force {
        for item in &converted {
            let target = output.unwrap_or(&item.target);
            if target.exists() {
                return Err(miette!(
                    help = "Pass --force to overwrite it.",
                    "{} already exists.",
                    target.display()
                ));
            }
        }
    }
    for item in &converted {
        let target = output.unwrap_or(&item.target);
        migrate::write_converted(item, output, force)?;
        println!("{} -> {}", item.source.display(), target.display());
    }
    info!("sign the new file(s) with `pm sign`; signatures do not carry over");
    Ok(())
}

/// Writes the example build file to `file`.
///
/// # Errors
///
/// Fails if `file` exists and `force` is false, or if it cannot be written.
fn generate(file: &Path, force: bool) -> miette::Result<()> {
    let example = if recipe::is_rhai(file) {
        recipe::render(&BuildFile::generate())?
    } else if star::is_starlark(file) {
        return Err(miette!(
            help = format!(
                "Recipes are Rhai now: `pm generate {}`.",
                file.with_extension(recipe::EXTENSION).display()
            ),
            "Starlark recipes are deprecated and are not generated."
        ));
    } else {
        warn!(
            file = %file.display(),
            "YAML build files are deprecated; name the file `.rhai` to get a Rhai recipe"
        );
        to_string(&BuildFile::generate()).into_diagnostic()?
    };

    if force {
        // This pre-check is racy, deliberately: `--force` already opted into
        // clobbering whatever is at the path, so the answer only decides
        // whether the replacement is worth a warning.
        let replaced = file.exists();
        write(file, &example).into_diagnostic().wrap_err_with(|| {
            format!(
                "Could not write the example build file to {}",
                file.display()
            )
        })?;
        if replaced {
            warn!(file = %file.display(), "replaced an existing file");
        }
    } else {
        // `create_new` folds "does this exist?" and "create it" into one
        // syscall, so a file that appears between the two is rejected by the
        // kernel instead of being silently truncated, which a `Path::exists`
        // pre-check followed by a plain write would do.
        let opened = OpenOptions::new().write(true).create_new(true).open(file);
        let mut handle = match opened {
            Ok(handle) => handle,
            Err(source) if source.kind() == ErrorKind::AlreadyExists => {
                return Err(miette!(
                    help = "Pass --force to overwrite it.",
                    "The path {} already exists.",
                    file.display()
                ));
            }
            Err(source) => {
                return Err(source)
                    .into_diagnostic()
                    .wrap_err_with(|| format!("Could not create {}", file.display()));
            }
        };
        handle
            .write_all(example.as_bytes())
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "Could not write the example build file to {}",
                    file.display()
                )
            })?;
    }

    info!(file = %file.display(), "wrote example build file");
    Ok(())
}

/// Signs `file`, generating and trusting the signing key on first use.
///
/// The paths and the public key go to stdout: they are this subcommand's
/// primary output, and the public key is meant to be copied to whoever has to
/// verify the result.
///
/// # Errors
///
/// Fails if `file` does not exist, if the key cannot be loaded or created, if
/// the new key cannot be trusted, or if the signature cannot be written.
fn sign(file: &Path, key: Option<PathBuf>, trust_dir: Option<PathBuf>) -> miette::Result<()> {
    if !file.exists() {
        return Err(miette!("The path {} does not exist.", file.display()));
    }

    let key_path = resolve_key_path(key)?;
    // Asked before the key is loaded, because `load_or_create` erases the
    // difference: afterwards there is no way to tell a key it just generated
    // from one that was already there.
    let generated = !key_path.exists();

    let signing_key = SigningKey::load_or_create(&key_path)?;
    let public_key = signing_key.public_key_hex();

    if generated {
        // `load_or_create` warns that the key is new; trusting it here is what
        // keeps `pm sign` from producing a signature the same machine rejects.
        let dir = resolve_trust_dir(trust_dir)?;
        TrustStore::load(&dir)?.add(&public_key, &dir)?;
        warn!(
            path = %key_path.display(),
            "generated a new signing key and trusted it locally; back it up, it cannot be recovered"
        );
    }

    let signature = sign_file(file, &signing_key)?;

    println!("{:<LABEL_WIDTH$}{}", "signed:", file.display());
    println!("{:<LABEL_WIDTH$}{}", "signature:", signature.display());
    println!("{:<LABEL_WIDTH$}{}", "key:", key_path.display());
    println!("{:<LABEL_WIDTH$}{public_key}", "public key:");
    Ok(())
}

/// Creates the signing key, refusing to destroy an existing one without `force`.
///
/// The public key goes to stdout: producing it is the point of the subcommand,
/// and it has to be pasteable into whatever trusts this machine.
///
/// # Errors
///
/// Fails if a key already exists and `force` is false, if the old key cannot be
/// removed, or if the new key cannot be generated or trusted.
fn keygen(force: bool, key: Option<PathBuf>, trust_dir: Option<PathBuf>) -> miette::Result<()> {
    let key_path = resolve_key_path(key)?;

    if key_path.exists() {
        if !force {
            return Err(miette!(
                help = "Pass --force to destroy it and start over. Everything signed with \
                        the old key then has to be signed again, and every machine that \
                        trusted it has to trust the new one.",
                "A signing key already exists at {}.",
                key_path.display()
            ));
        }
        warn!(
            path = %key_path.display(),
            "--force was given: destroying the existing signing key, which cannot be undone"
        );
        remove_file(&key_path)
            .into_diagnostic()
            .wrap_err_with(|| format!("Could not remove the signing key {}", key_path.display()))?;
    }

    let signing_key = SigningKey::load_or_create(&key_path)?;
    let public_key = signing_key.public_key_hex();

    let dir = resolve_trust_dir(trust_dir)?;
    TrustStore::load(&dir)?.add(&public_key, &dir)?;

    println!("{:<LABEL_WIDTH$}{}", "key:", key_path.display());
    println!("{:<LABEL_WIDTH$}{public_key}", "public key:");
    Ok(())
}

/// Adds a public key to the trust store.
///
/// `key` is either the hex itself or a path to a file holding it. A file that
/// parses as a detached signature contributes its signer, which is how a
/// package and the key that signed it can be trusted from the same two files.
///
/// # Errors
///
/// Fails if the file cannot be read, if the key is not valid Ed25519 public key
/// hex, or if the trust store cannot be written.
fn trust(key: &str, trust_dir: Option<PathBuf>) -> miette::Result<()> {
    let path = Path::new(key);
    let public_key = if path.is_file() {
        let text = read_to_string(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("Could not read {}", path.display()))?;
        match Signature::from_yaml(&text) {
            Ok(signature) => {
                info!(path = %path.display(), "taking the signer of this signature");
                signature.public_key_hex().to_owned()
            }
            // Not a signature, so the file is a bare key. `TrustStore::add`
            // validates the hex and says so precisely if it is not one.
            Err(_) => text.trim().to_owned(),
        }
    } else {
        key.trim().to_owned()
    };

    let dir = resolve_trust_dir(trust_dir)?;
    let mut store = TrustStore::load(&dir)?;
    if store.trusts(&public_key) {
        info!(public_key = %public_key, dir = %dir.display(), "already trusted");
        return Ok(());
    }
    store.add(&public_key, &dir)
}

/// The signing key path, `--key` winning over the default location.
///
/// # Errors
///
/// Fails if no default config directory can be determined.
fn resolve_key_path(key: Option<PathBuf>) -> miette::Result<PathBuf> {
    key.map_or_else(default_key_path, Ok)
}

/// The trust store directory, `--trust-dir` winning over the default location.
///
/// # Errors
///
/// Fails if no default config directory can be determined.
fn resolve_trust_dir(trust_dir: Option<PathBuf>) -> miette::Result<PathBuf> {
    trust_dir.map_or_else(default_trust_dir, Ok)
}

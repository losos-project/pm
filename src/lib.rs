//! pm's build core: build files, their dependency graph, the plugins and policy
//! that classify their steps, the sandbox they run in, and the permissions a
//! package is found to need.
//!
//! The layers below that core are crates of their own under `crates/`, and are
//! re-exported here under the module names they always had, so `pm::signing`,
//! `pm::wire` and the rest still resolve.

/// Build-file parsing, building and packaging.
pub mod bf;
/// A best-effort cancellation token threaded through a build.
pub use pm_cancel as cancel;
/// The caller-supplied environment a build runs against, instead of the
/// process's own cwd, `$PATH` and `$HOME`.
pub mod context;
/// The daemon side of `pm`: the one-job-per-process worker today, and the
/// `org.pm1` D-Bus service once a later task adds it.
pub mod daemon;
/// Fetching a build file's sources over HTTP, hashing them as they land.
pub use pm_download as download;
/// Resolving a build file's dependency graph, and building it.
pub mod graph;
/// The host's persistent virtual machines, made from templates, for `pm machine`.
pub mod machine;
/// Package metadata written into each archive.
pub mod metadata;
/// Converting YAML and Starlark build files to Rhai recipes.
pub mod migrate;
/// Inferring the permissions a package actually needs, from its source, its
/// built objects and a traced execution.
pub mod perms;
/// Extending pm's built-in tables with sandboxed WebAssembly components.
pub mod plugin;
/// Deriving a sandbox policy from the contents of a build file.
pub mod policy;
/// A live, redrawable region that reports what a build is doing right now.
pub use pm_progress as progress;
/// Recipes written in Rhai.
pub mod recipe;
/// Extracting and running a built package inside a sandbox.
pub mod run;
/// The hakoniwa jail that build steps run inside.
pub mod sandbox;
/// Ed25519 signing and verification of build files and packages.
pub use pm_signing as signing;
/// Build files written in Starlark, deprecated in favour of [`recipe`].
pub mod star;
/// Individual build steps and their stages.
pub mod step;
/// Small text-formatting helpers shared by the library and the binaries.
pub use pm_text as text;
/// Packages that ship their own kernel, booted in a virtual machine.
pub use pm_vm as vm;
/// Types and framing that cross the boundary between the daemon and its
/// clients or its own worker.
pub use pm_wire as wire;
/// RAII guards that auto-close build workspaces and sandboxed child processes.
pub use pm_workspace as workspace;

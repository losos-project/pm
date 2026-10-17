//! Build pm's bundled plugins and test fixtures from `plugins/` and encode them as components.
//!
//! The components are not checked in. Every build compiles the bundled plugins and test
//! fixtures in release mode with a nested cargo invocation over the `plugins/` workspace.
//! [`pm::plugin::bundled`] embeds only the bundled results; test fixtures are written to
//! `OUT_DIR` and never embedded in pm.
//! That needs two things a plain Rust build does not:
//!
//! - the `wasm32-unknown-unknown` and `wasm32-wasip2` targets;
//! - a C compiler that targets wasm32, which is clang - the tree-sitter grammars are C.
//!
//! The nested build has its own target directory, `bundled-plugins/` next to pm's own
//! profiles, so it never contends for the lock the outer build holds and is shared by
//! `cargo build`, `cargo test` and `cargo clippy` - each of which runs this script with
//! a different `OUT_DIR` - instead of building every plugin once per profile. It is
//! incremental: after the first build it only reruns when something under `plugins/`
//! or `wit/` changes.

use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use wit_component::ComponentEncoder;

const TARGET: &str = "wasm32-unknown-unknown";

/// Every bundled plugin crate, by the name `src/plugin/bundled.rs` embeds it under.
/// Each is the package `bundled-<name>` in the `plugins/` workspace.
const BUNDLED: [&str; 14] = [
    "buildsys",
    "rust",
    "go",
    "node",
    "python",
    "c",
    "posix",
    "git",
    "c-source",
    "cpp-source",
    "rust-source",
    "python-source",
    "go-source",
    "bash-source",
];

/// Example and adversarial plugins used by integration tests, not embedded in pm.
const TEST_PLUGINS: [&str; 12] = [
    "libvirt",
    "quickemu",
    "systemd",
    "sysext",
    "sysupdate",
    "zig",
    "greedy",
    "runaway",
    "nameless",
    "scanner",
    "recipes",
    "launcher",
];

/// Variables cargo sets for this build script that describe pm's own build. Passed
/// through, they would make the nested cargo build the plugins with pm's flags or into
/// pm's target directory.
const NOT_INHERITED: [&str; 6] = [
    "CARGO_ENCODED_RUSTFLAGS",
    "RUSTFLAGS",
    "CARGO_TARGET_DIR",
    "CARGO_BUILD_TARGET",
    "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_PRIMARY_PACKAGE",
];

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("set by cargo"));
    let plugins = root.join("plugins");

    for path in [
        "plugins/Cargo.toml",
        "plugins/Cargo.lock",
        "plugins/bundled",
        "plugins/fixtures",
        "plugins/libvirt",
        "plugins/quickemu",
        "plugins/systemd",
        "plugins/sysext",
        "plugins/sysupdate",
        "plugins/unitfile",
        "plugins/zig",
        "plugins/vendor",
        "wit",
    ] {
        println!("cargo::rerun-if-changed={path}");
    }

    assert!(
        plugins.join("Cargo.toml").is_file(),
        "{} is missing: pm builds its bundled plugins from it, so pm builds only from a \
         checkout of its repository",
        plugins.display()
    );

    let target_dir = shared_target_dir(&out);
    compile(&plugins, &target_dir);

    let components = out.join("bundled");
    fs::create_dir_all(&components).expect("create the bundled components directory");
    for name in BUNDLED {
        let module = target_dir
            .join(TARGET)
            .join("release")
            .join(format!("bundled_{}.wasm", name.replace('-', "_")));
        encode(&module, &components.join(format!("{name}.wasm")));
    }

    let test_components = out.join("test-plugins");
    fs::create_dir_all(&test_components).expect("create the plugin test fixtures directory");
    for name in TEST_PLUGINS {
        let module = target_dir
            .join(TARGET)
            .join("release")
            .join(format!("{}.wasm", name.replace('-', "_")));
        encode(&module, &test_components.join(format!("{name}.wasm")));
    }
    compile_wasi_fixture(&plugins, &target_dir);
    copy_if_changed(
        &target_dir.join("wasm32-wasip2/release/wasi.wasm"),
        &test_components.join("wasi.wasm"),
    );
    println!(
        "cargo::rustc-env=PM_TEST_PLUGIN_DIR={}",
        test_components.display()
    );
}

/// `bundled-plugins/` in pm's target directory, found as the ancestor of `OUT_DIR` that
/// cargo marked with a `CACHEDIR.TAG`; `OUT_DIR` itself if there is none.
fn shared_target_dir(out: &Path) -> PathBuf {
    out.ancestors()
        .find(|dir| dir.join("CACHEDIR.TAG").is_file())
        .map_or_else(
            || out.join("plugins-target"),
            |root| root.join("bundled-plugins"),
        )
}

/// Build bundled plugins and integration-test components from the `plugins/` workspace.
fn compile(plugins: &Path, target_dir: &Path) {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let include = plugins.join("vendor/tree-sitter-language/wasm/include");

    let mut command = Command::new(cargo);
    command
        .current_dir(plugins)
        .args(["build", "--release", "--locked", "--target", TARGET])
        .arg("--target-dir")
        .arg(target_dir)
        // The grammars include a handful of libc headers that wasm32-unknown-unknown
        // has none of; the vendored tree-sitter-language ships them.
        .env(
            "CFLAGS_wasm32_unknown_unknown",
            format!("-I{}", include.display()),
        );
    for name in BUNDLED {
        command.arg("-p").arg(format!("bundled-{name}"));
    }
    for name in TEST_PLUGINS {
        command.arg("-p").arg(name);
    }
    for key in NOT_INHERITED {
        command.env_remove(key);
    }

    let status = command
        .status()
        .unwrap_or_else(|error| panic!("cannot run cargo to build the plugins: {error}"));
    assert!(
        status.success(),
        "building pm's plugins failed ({status}). They are WebAssembly: this needs \
         `rustup target add {TARGET}` and clang on PATH for the C grammars"
    );
}

/// Build the one fixture whose imports intentionally require a WASI host.
fn compile_wasi_fixture(plugins: &Path, target_dir: &Path) {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let mut command = Command::new(cargo);
    command
        .current_dir(plugins)
        .args([
            "build",
            "--release",
            "--locked",
            "--target",
            "wasm32-wasip2",
            "--target-dir",
        ])
        .arg(target_dir)
        .arg("-p")
        .arg("wasi");
    for key in NOT_INHERITED {
        command.env_remove(key);
    }
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("cannot run cargo to build the WASI test fixture: {error}"));
    assert!(
        status.success(),
        "building the WASI plugin test fixture failed ({status}); this needs \
         `rustup target add wasm32-wasip2`"
    );
}

/// Wrap the core module at `module` in a component and write it to `component`.
///
/// Validation is on, so a module that does not make a valid component fails the build
/// here rather than failing to load in pm.
fn encode(module: &Path, component: &Path) {
    let bytes = fs::read(module)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", module.display()));
    let encoded = ComponentEncoder::default()
        .module(&bytes)
        .and_then(|encoder| encoder.validate(true).encode())
        .unwrap_or_else(|error| {
            panic!(
                "cannot encode {} as a component: {error:?}",
                module.display()
            )
        });
    copy_bytes_if_changed(&encoded, component);
}

/// Copy `source` into `destination` only when the bytes differ.
fn copy_if_changed(source: &Path, destination: &Path) {
    let bytes = fs::read(source)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", source.display()));
    copy_bytes_if_changed(&bytes, destination);
}

fn copy_bytes_if_changed(bytes: &[u8], destination: &Path) {
    // Rewriting an unchanged file would make cargo rebuild pm for nothing.
    if fs::read(destination).ok().as_deref() != Some(bytes) {
        fs::write(destination, bytes)
            .unwrap_or_else(|error| panic!("cannot write {}: {error}", destination.display()));
    }
}

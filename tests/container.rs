//! `pm container`, end to end through the CLI: the `podman` plugin plans each request
//! and pm runs the plan, with stand-ins for `podman` and `podman-compose` that log
//! what they are asked and keep which containers there are as files, so these need
//! no Podman.
//!
//! The plugin refuses root, so what these see depends on who runs them: as anyone
//! else every request reaches the stand-ins, and as root none does. The plugin's own
//! tests check its answers themselves.

use std::{
    fs::{self, create_dir_all, read_to_string, set_permissions, write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    process::{Command, Output},
};

use tempfile::{TempDir, tempdir};

/// The stand-ins, one script for both, by the name it is called by: every call
/// appended to `$LOG`, each container a file in `$STATE` holding its state.
const STAND_IN: &str = r#"#!/bin/sh
program=${0##*/}
echo "$program $*" >> "$LOG"
case "$program" in
  podman-compose)
    [ "$1" = --version ] && { echo "podman-compose version 1.5.0"; exit; }
    # --file FILE up|down ...: the one container every compose file here makes.
    case "$3" in
      up) [ "$4" = --no-start ] && echo created > "$STATE/web" || echo running > "$STATE/web" ;;
      down) rm -f "$STATE/web" ;;
    esac ;;
  podman)
    case "$1" in
      --version) echo "podman version 5.6.1" ;;
      ps) for c in "$STATE"/*; do [ -e "$c" ] && echo "${c##*/}"; done; true ;;
      inspect) cat "$STATE/$5" ;;
      port) [ -e "$STATE/$3" ] && echo "8006/tcp -> 127.0.0.1:41234" ;;
      container)
        [ -e "$STATE/$4" ] || { echo "Error: no container with name or ID \"$4\" found" >&2; exit 125; }
        case "$2" in
          start|unpause) echo running > "$STATE/$4" ;;
          stop) echo exited > "$STATE/$4" ;;
          pause) echo paused > "$STATE/$4" ;;
          rm) rm "$STATE/$4" ;;
        esac ;;
      *) echo "podman: unexpected $1" >&2; exit 2 ;;
    esac ;;
esac
"#;

/// A host for `pm container`: the podman plugin, the stand-ins on `PATH` and a
/// compose file.
struct Host {
    root: TempDir,
}

impl Host {
    fn new() -> Self {
        let root = tempdir().expect("a temporary directory");
        let path = root.path();
        for dir in ["bin", "plugins", "state"] {
            create_dir_all(path.join(dir)).expect("make the host's directories");
        }
        fs::copy(
            PathBuf::from(env!("PM_TEST_PLUGIN_DIR")).join("podman.wasm"),
            path.join("plugins/podman.wasm"),
        )
        .expect("stage the podman plugin");
        for program in ["podman", "podman-compose"] {
            let stand_in = path.join("bin").join(program);
            write(&stand_in, STAND_IN).expect("write a stand-in");
            set_permissions(&stand_in, fs::Permissions::from_mode(0o755))
                .expect("make it executable");
        }
        write(
            path.join("compose.yml"),
            "services:\n  web:\n    image: nginx\n    container_name: web\n",
        )
        .expect("write a compose file");
        write(path.join("log"), "").expect("start the log");
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn pm(&self, args: &[&str]) -> Output {
        let path = format!(
            "{}:{}",
            self.path("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        Command::new(env!("CARGO_BIN_EXE_pm"))
            .arg("--plugin-dir")
            .arg(self.path("plugins"))
            .arg("--allow-unsigned-plugins")
            .arg("container")
            .args(args)
            .env("PATH", path)
            .env("LOG", self.path("log"))
            .env("STATE", self.path("state"))
            .output()
            .expect("run pm")
    }

    fn ok(&self, args: &[&str]) -> String {
        let output = self.pm(args);
        assert!(
            output.status.success(),
            "pm container {args:?} failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("pm prints text")
    }

    /// The stand-ins' calls since the last time this was asked, with the host's
    /// directory as `$H`.
    fn calls(&self) -> Vec<String> {
        let log = read_to_string(self.path("log")).expect("read the log");
        write(self.path("log"), "").expect("clear the log");
        let here = fs::canonicalize(self.root.path()).expect("the host's directory");
        log.lines()
            .map(|line| line.replace(here.to_str().unwrap(), "$H"))
            .collect()
    }
}

fn root() -> bool {
    fs::metadata("/proc/self").is_ok_and(|me| me.uid() == 0)
}

#[test]
fn a_compose_file_comes_up_and_its_container_is_managed_by_name() {
    if root() {
        return;
    }
    let host = Host::new();
    let compose = host.path("compose.yml");
    let compose = compose.to_str().unwrap();

    host.ok(&["up", compose]);
    assert_eq!(
        host.calls(),
        ["podman-compose --file $H/compose.yml up --detach"]
    );
    assert_eq!(host.ok(&["list"]), "web\n");
    assert_eq!(host.ok(&["status", "web"]), "running\n");
    assert_eq!(host.ok(&["ports", "web"]), "8006/tcp -> 127.0.0.1:41234\n");
    host.calls();

    host.ok(&["pause", "web"]);
    host.ok(&["unpause", "web"]);
    host.ok(&["stop", "web"]);
    assert_eq!(host.ok(&["status", "web"]), "exited\n");
    host.ok(&["start", "web"]);
    host.ok(&["stop", "web"]);
    host.ok(&["remove", "web"]);
    assert_eq!(
        host.calls(),
        [
            "podman container pause -- web",
            "podman container unpause -- web",
            "podman container stop -- web",
            "podman inspect --format {{.State.Status}} -- web",
            "podman container start -- web",
            "podman container stop -- web",
            "podman container rm -- web",
        ]
    );
    assert_eq!(host.ok(&["list"]), "");

    host.ok(&["create", compose]);
    assert_eq!(host.ok(&["status", "web"]), "created\n");
    host.ok(&["down", compose]);
    assert_eq!(host.ok(&["list"]), "");
}

#[test]
fn what_runs_containers_tells_its_versions() {
    if root() {
        return;
    }
    let host = Host::new();
    let versions = host.ok(&["version"]);
    assert!(versions.contains("podman version 5.6.1"), "{versions}");
    assert!(
        versions.contains("podman-compose version 1.5.0"),
        "{versions}"
    );
}

#[test]
fn a_failed_step_fails_the_request() {
    if root() {
        return;
    }
    let host = Host::new();
    let output = host.pm(&["start", "missing"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no container with name"), "{stderr}");
}

#[test]
fn root_is_refused_before_anything_runs() {
    if !root() {
        return;
    }
    let host = Host::new();
    let output = host.pm(&["list"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("rootless"), "{stderr}");
    assert!(host.calls().is_empty());
}

#[test]
fn names_and_files_are_checked_before_the_plugin_sees_them() {
    let host = Host::new();
    for args in [
        ["start", "web; rm -rf ~"],
        ["status", "-x"],
        ["up", "/nonexistent/compose.yml"],
    ] {
        let output = host.pm(&args);
        assert!(!output.status.success(), "{args:?}");
    }
    assert!(host.calls().is_empty());
}

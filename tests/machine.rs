//! `pm machine`, end to end through the CLI: the `libvirt` plugin plans each request
//! and pm runs the plan against a stand-in `virsh` that keeps the host's state as
//! files, so these need no libvirt.
//!
//! The stand-in knows what a real `virsh` answers for the commands the plugin uses -
//! `vol-info` fails for a missing volume, `domjobinfo` fails for a machine that is
//! not running - and fails whichever command `$FAIL` names, to see what pm takes
//! back. `tests/vm_plugins.rs` checks the plugin's answers themselves.
//!
//! One test runs against a real libvirt daemon, when asked:
//!
//! ```sh
//! cargo test --test machine -- --ignored
//! ```
//!
//! It needs `virsh`, `qemu-img` and a daemon at libvirt's default URI with a
//! `default` storage pool, and leaves nothing behind.

use std::{
    fs::{self, create_dir_all, read_to_string, set_permissions, write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use tempfile::{TempDir, tempdir};

/// The stand-in: every call appended to `$LOG`, state as files under `$STATE`.
const FAKE_VIRSH: &str = r#"#!/bin/sh
echo "$*" >> "$LOG"
[ "$1" = -q ] && shift
[ -n "$FAIL" ] && [ "$1" = "$FAIL" ] && { echo "virsh: $1 failed on purpose" >&2; exit 1; }
case "$1" in
  vol-info) [ -e "$STATE/vol-$4" ] ;;
  vol-create-as) [ ! -e "$STATE/vol-$3" ] && touch "$STATE/vol-$3" ;;
  vol-upload) cp "$5" "$STATE/vol-$4" ;;
  vol-delete) rm "$STATE/vol-$4" ;;
  pool-refresh) : ;;
  define) name=$(sed -n 's:.*<name>\(.*\)</name>.*:\1:p' "$2"); [ ! -e "$STATE/domain-$name" ] && cp "$2" "$STATE/domain-$name" ;;
  undefine) rm "$STATE/domain-$2" && rm -f "$STATE/vol-pm-machine-$2.qcow2" ;;
  domjobinfo) [ -e "$STATE/running-$2" ] ;;
  start) [ -e "$STATE/domain-$2" ] && touch "$STATE/running-$2" ;;
  shutdown|destroy) rm "$STATE/running-$2" ;;
  list) echo " Id   Name   State"; for d in "$STATE"/domain-*; do [ -e "$d" ] && echo " -    ${d##*/domain-}"; done ;;
  *) echo "virsh: unexpected $1" >&2; exit 2 ;;
esac
"#;

/// A host for `pm machine`: the libvirt plugin, the stand-in on `PATH`, and a
/// template image.
struct Host {
    root: TempDir,
}

impl Host {
    fn new() -> Self {
        let root = tempdir().expect("a temporary directory");
        let path = root.path();
        for dir in ["bin", "plugins", "state", "share/pm/machines"] {
            create_dir_all(path.join(dir)).expect("make the host's directories");
        }
        fs::copy(
            Path::new(env!("PM_TEST_PLUGIN_DIR")).join("libvirt.wasm"),
            path.join("plugins/libvirt.wasm"),
        )
        .expect("stage the libvirt plugin");
        let virsh = path.join("bin/virsh");
        write(&virsh, FAKE_VIRSH).expect("write the stand-in virsh");
        set_permissions(&virsh, fs::Permissions::from_mode(0o755)).expect("make it executable");
        write(path.join("Guest.img"), [0u8; 4096]).expect("write a template image");
        write(path.join("Win11.iso"), [1u8; 4096]).expect("write an installer CD");
        write(path.join("log"), "").expect("start the log");
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn pm(&self, args: &[&str], fail: Option<&str>) -> Output {
        let path = format!(
            "{}:{}",
            self.path("bin").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let mut command = Command::new(env!("CARGO_BIN_EXE_pm"));
        command
            .arg("--plugin-dir")
            .arg(self.path("plugins"))
            .arg("--allow-unsigned-plugins")
            .args(args)
            .env("PATH", path)
            .env("LOG", self.path("log"))
            .env("STATE", self.path("state"))
            // Where the host's CDs of guest tools are looked for: here, so the
            // runner's own never answer.
            .env("XDG_DATA_DIRS", self.path("share"))
            .env_remove("FAIL");
        if let Some(fail) = fail {
            command.env("FAIL", fail);
        }
        command.output().expect("run pm")
    }

    fn ok(&self, args: &[&str]) -> String {
        let output = self.pm(args, None);
        assert!(
            output.status.success(),
            "pm {args:?} failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("pm prints text")
    }

    /// The `virsh` calls since the last time this was asked, without `-q`.
    fn calls(&self) -> Vec<String> {
        let log = read_to_string(self.path("log")).expect("read the log");
        write(self.path("log"), "").expect("clear the log");
        log.lines()
            .map(|line| line.strip_prefix("-q ").unwrap_or(line).to_owned())
            .collect()
    }

    fn state(&self, name: &str) -> bool {
        self.path("state").join(name).exists()
    }

    fn create(&self, name: &str) -> Output {
        self.pm(
            &[
                "machine",
                "create",
                name,
                "--image",
                self.path("Guest.img").to_str().unwrap(),
                "--label",
                "blue",
            ],
            None,
        )
    }
}

/// `vol-<name>` for the template the host's image becomes.
fn template_volume(host: &Host) -> String {
    fs::read_dir(host.path("state"))
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .find(|name| name.starts_with("vol-pm-template-guest-"))
        .expect("the template is installed")
}

#[test]
fn the_first_machine_installs_the_template_and_the_second_reuses_it() {
    let host = Host::new();
    assert!(host.create("work").status.success());
    let first = host.calls();
    let template = template_volume(&host);
    let volume = template.strip_prefix("vol-").unwrap();
    assert!(volume.ends_with(".raw"), "{volume}");
    assert_eq!(
        first,
        [
            format!("vol-info --pool default {volume}"),
            format!("vol-create-as default {volume} 4096B --format raw"),
            format!(
                "vol-upload --pool default {volume} {} --sparse",
                host.path("Guest.img").canonicalize().unwrap().display()
            ),
            "pool-refresh default".into(),
            format!(
                "vol-create-as default pm-machine-work.qcow2 34359738368B --format qcow2 \
                 --backing-vol {volume} --backing-vol-format raw"
            ),
            "define domain.xml".into(),
        ]
    );
    let domain = read_to_string(host.path("state/domain-work")).unwrap();
    assert!(domain.contains("<pm:label>blue</pm:label>"), "{domain}");

    assert!(host.create("personal").status.success());
    let second = host.calls();
    assert_eq!(second.len(), 3, "{second:?}");
    assert!(second[1].starts_with("vol-create-as default pm-machine-personal.qcow2"));
    assert_eq!(second[2], "define domain.xml");
}

#[test]
fn a_failed_definition_takes_the_new_template_and_disk_back() {
    let host = Host::new();
    let output = host.pm(
        &[
            "machine",
            "create",
            "work",
            "--image",
            host.path("Guest.img").to_str().unwrap(),
        ],
        Some("define"),
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("define the machine work"), "{stderr}");
    let calls = host.calls();
    let template = calls[1].split(' ').nth(2).unwrap();
    let forget = format!("vol-delete --pool default {template}");
    assert_eq!(
        calls[calls.len() - 3..],
        [
            "vol-delete --pool default pm-machine-work.qcow2".to_owned(),
            forget.clone(),
            forget,
        ],
        "the disk, then the template once per step that made it: {calls:?}"
    );
    let left: Vec<_> = fs::read_dir(host.path("state")).unwrap().collect();
    assert!(left.is_empty(), "nothing stays behind: {left:?}");
}

#[test]
fn a_disk_that_exists_already_is_not_deleted_by_the_failure_it_causes() {
    let host = Host::new();
    write(
        host.path("state/vol-pm-machine-work.qcow2"),
        "someone else's",
    )
    .unwrap();
    let output = host.pm(
        &[
            "machine",
            "create",
            "work",
            "--image",
            host.path("Guest.img").to_str().unwrap(),
        ],
        None,
    );
    assert!(!output.status.success());
    assert_eq!(
        read_to_string(host.path("state/vol-pm-machine-work.qcow2")).unwrap(),
        "someone else's"
    );
    // The template it installed on the way is taken back, though.
    let calls = host.calls();
    assert!(
        calls
            .last()
            .unwrap()
            .starts_with("vol-delete --pool default pm-template-")
    );
    assert!(!host.state("domain-work"));
}

#[test]
fn start_stop_and_remove_follow_the_machine_state() {
    let host = Host::new();
    assert!(host.create("work").status.success());
    host.calls();

    host.ok(&["machine", "start", "work"]);
    assert!(host.state("running-work"));
    host.ok(&["machine", "start", "work"]);
    assert_eq!(
        host.calls(),
        [
            "domjobinfo work",
            "start work",
            // Running already: asked, and left alone.
            "domjobinfo work",
        ]
    );

    host.ok(&["machine", "stop", "work"]);
    host.ok(&["machine", "kill", "work"]);
    assert_eq!(
        host.calls(),
        ["domjobinfo work", "shutdown work", "domjobinfo work"]
    );

    let listed = host.ok(&["machine", "list"]);
    assert!(listed.contains("work"), "{listed}");
    host.calls();

    host.ok(&["machine", "start", "work"]);
    host.calls();
    host.ok(&["machine", "remove", "work"]);
    assert_eq!(
        host.calls(),
        [
            "domjobinfo work",
            "destroy work",
            "undefine work --nvram --storage vda"
        ]
    );
    assert!(!host.state("domain-work"));
    assert!(!host.state("vol-pm-machine-work.qcow2"));
    // The template stays for the next machine.
    template_volume(&host);
}

#[test]
fn a_windows_machine_installs_from_its_cd_and_the_hosts_drivers() {
    let host = Host::new();
    let win11 = host.path("Win11.iso");
    let args = [
        "machine",
        "create",
        "win",
        "--installer",
        win11.to_str().unwrap(),
        "--system",
        "windows",
        "--label",
        "red",
    ];
    // Without the host's drivers CD, Windows Setup would find no disk to install
    // on, so pm stops before asking anything of libvirt.
    let output = host.pm(&args, None);
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    // miette wraps the message to the terminal's width, anywhere.
    assert!(error.contains("windows-tools.iso"), "{error}");
    assert!(host.calls().is_empty());

    write(
        host.path("share/pm/machines/windows-tools.iso"),
        [2u8; 4096],
    )
    .expect("install the host's drivers CD");
    host.ok(&args);
    let calls = host.calls();
    let uploads: Vec<&str> = calls
        .iter()
        .filter_map(|call| call.strip_prefix("vol-upload --pool default "))
        .collect();
    assert_eq!(uploads.len(), 2, "{calls:?}");
    assert!(uploads[0].starts_with("pm-media-win11-"), "{uploads:?}");
    assert!(
        uploads[1].starts_with("pm-media-windows-tools-"),
        "{uploads:?}"
    );
    // Windows 11's least: 64 GiB of disk, with nothing under it.
    assert!(
        calls.contains(
            &"vol-create-as default pm-machine-win.qcow2 68719476736B --format qcow2".to_owned()
        ),
        "{calls:?}"
    );
    let domain = read_to_string(host.path("state/domain-win")).expect("the machine is defined");
    for expected in [
        "<memory unit='MiB'>4096</memory>",
        "<pm:system>windows</pm:system>",
        "<pm:label>red</pm:label>",
        "<tpm model='tpm-crb'>",
    ] {
        assert!(domain.contains(expected), "{expected} in\n{domain}");
    }

    // A second machine from the same CDs uploads neither again, and removing
    // one leaves them for the other.
    let mut second = args;
    second[2] = "win2";
    host.ok(&second);
    assert!(
        !host
            .calls()
            .iter()
            .any(|call| call.starts_with("vol-upload")),
        "the CDs were uploaded again"
    );
    host.ok(&["machine", "remove", "win"]);
    assert!(host.state("domain-win2"));
    assert!(
        fs::read_dir(host.path("state"))
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("vol-pm-media-")
            })
            .count()
            == 2
    );
}

#[test]
fn an_image_and_installer_cds_do_not_go_together() {
    let host = Host::new();
    let output = host.pm(
        &[
            "machine",
            "create",
            "work",
            "--image",
            host.path("Guest.img").to_str().unwrap(),
            "--installer",
            host.path("Win11.iso").to_str().unwrap(),
        ],
        None,
    );
    assert!(!output.status.success());
    let output = host.pm(&["machine", "create", "work", "--system", "windows"], None);
    assert!(!output.status.success());
    assert!(host.calls().is_empty());
}

#[test]
fn names_no_machine_could_have_are_refused_before_any_plugin_sees_them() {
    let host = Host::new();
    for name in ["Work", "../work", "work;rm", "-q"] {
        let output = host.pm(&["machine", "start", "--", name], None);
        assert!(!output.status.success(), "{name}");
    }
    assert!(host.calls().is_empty());
}

#[test]
fn without_a_plugin_that_manages_machines_pm_says_what_is_missing() {
    let host = Host::new();
    fs::remove_file(host.path("plugins/libvirt.wasm")).unwrap();
    let output = host.pm(&["machine", "list"], None);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no plugin manages machines"), "{stderr}");
}

/// Against a real libvirt: make a machine from a tiny qcow2, check libvirt has it
/// with its label, and remove it again, template and all.
#[test]
#[ignore = "needs virsh, qemu-img and a libvirt daemon with a default pool"]
fn a_real_libvirt_gets_the_machine() {
    let root = tempdir().unwrap();
    let plugins = root.path().join("plugins");
    create_dir_all(&plugins).unwrap();
    fs::copy(
        Path::new(env!("PM_TEST_PLUGIN_DIR")).join("libvirt.wasm"),
        plugins.join("libvirt.wasm"),
    )
    .unwrap();
    let image = root.path().join("pm-test-template.qcow2");
    let made = Command::new("qemu-img")
        .args(["create", "-f", "qcow2"])
        .arg(&image)
        .arg("64M")
        .status()
        .unwrap();
    assert!(made.success());

    let pm = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_pm"))
            .arg("--plugin-dir")
            .arg(&plugins)
            .arg("--allow-unsigned-plugins")
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "pm {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    let name = format!("pm-test-{}", std::process::id());
    pm(&[
        "machine",
        "create",
        &name,
        "--image",
        image.to_str().unwrap(),
        "--label",
        "purple",
        "--memory",
        "256",
        "--cpus",
        "1",
        "--disk",
        "1",
    ]);
    let xml = Command::new("virsh")
        .args(["dumpxml", &name])
        .output()
        .unwrap();
    let xml = String::from_utf8_lossy(&xml.stdout);
    pm(&["machine", "remove", &name]);

    assert!(xml.contains("<pm:label>purple</pm:label>"), "{xml}");
    assert!(xml.contains("pm-machine-"), "{xml}");
    let volumes = Command::new("virsh")
        .args(["vol-list", "default"])
        .output()
        .unwrap();
    let volumes = String::from_utf8_lossy(&volumes.stdout);
    assert!(
        !volumes.contains(&format!("pm-machine-{name}")),
        "{volumes}"
    );
    let template = volumes
        .split_whitespace()
        .find(|word| {
            word.starts_with("pm-test-template") || word.starts_with("pm-template-pm-test-template")
        })
        .map(str::to_owned);
    if let Some(template) = template {
        let _ = Command::new("virsh")
            .args(["vol-delete", "--pool", "default", &template])
            .status();
    }
}

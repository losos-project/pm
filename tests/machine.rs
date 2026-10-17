//! `pm machine`, end to end through the CLI: the `quickemu` plugin plans each request
//! and pm runs the plan, with the real coreutils for the files and stand-ins for
//! `qemu-img`, `quickemu`, `systemd-run` and `systemctl`, which keep whether a
//! machine runs as files, so these need no QEMU and no service manager.
//!
//! The stand-ins answer as the real ones would for what the plugin asks -
//! `systemctl is-active` fails for a machine that does not run - and fail whichever
//! program `$FAIL` names, to see what pm takes back. The plugin's own tests check
//! its answers themselves.

use std::{
    fs::{self, create_dir_all, read_to_string, set_permissions, write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Output},
};

use tempfile::{TempDir, tempdir};

/// The stand-ins, one script for all four, by the name it is called by: every call
/// appended to `$LOG`, whether a machine runs as `$STATE/running-<unit>`.
const STAND_IN: &str = r#"#!/bin/sh
program=${0##*/}
echo "$program $*" >> "$LOG"
[ -n "$FAIL" ] && [ "$program" = "$FAIL" ] && { echo "$program failed on purpose" >&2; exit 1; }
case "$program" in
  qemu-img)
    # The disk is the next to last argument.
    eval "disk=\${$(($# - 1))}"
    [ ! -e "$disk" ] && echo qcow2 > "$disk" ;;
  systemd-run)
    for arg; do case "$arg" in --unit=*) unit=${arg#--unit=} ;; esac; done
    [ ! -e "$STATE/running-$unit" ] && touch "$STATE/running-$unit" ;;
  systemctl)
    [ "$1" = --user ] && shift
    case "$1" in
      --quiet) [ -e "$STATE/running-$3" ] ;;
      stop) rm "$STATE/running-$2" ;;
      list-units) for unit in "$STATE"/running-*; do [ -e "$unit" ] && echo "${unit##*/running-} loaded active running"; done; true ;;
      *) echo "systemctl: unexpected $1" >&2; exit 2 ;;
    esac ;;
  quickemu) : ;;
  *) echo "$program: unexpected" >&2; exit 2 ;;
esac
"#;

/// A host for `pm machine`: the quickemu plugin, the stand-ins on `PATH`, a template
/// image, and a home of its own to keep machines in.
struct Host {
    root: TempDir,
}

impl Host {
    fn new() -> Self {
        let root = tempdir().expect("a temporary directory");
        let path = root.path();
        for dir in ["bin", "plugins", "state", "data", "share/pm/machines"] {
            create_dir_all(path.join(dir)).expect("make the host's directories");
        }
        fs::copy(
            Path::new(env!("PM_TEST_PLUGIN_DIR")).join("quickemu.wasm"),
            path.join("plugins/quickemu.wasm"),
        )
        .expect("stage the quickemu plugin");
        for program in ["qemu-img", "quickemu", "systemd-run", "systemctl"] {
            let stand_in = path.join("bin").join(program);
            write(&stand_in, STAND_IN).expect("write a stand-in");
            set_permissions(&stand_in, fs::Permissions::from_mode(0o755))
                .expect("make it executable");
        }
        write(path.join("Guest.img"), [0u8; 4096]).expect("write a template image");
        write(path.join("Win11.iso"), [1u8; 4096]).expect("write an installer CD");
        write(path.join("log"), "").expect("start the log");
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    /// Where the plugin keeps the machines.
    fn machines(&self, name: &str) -> PathBuf {
        self.path("data/pm/machines").join(name)
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
            .env("XDG_DATA_HOME", self.path("data"))
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

    /// The stand-ins' calls since the last time this was asked, with the
    /// machines' directory as `$M`.
    fn calls(&self) -> Vec<String> {
        let log = read_to_string(self.path("log")).expect("read the log");
        write(self.path("log"), "").expect("clear the log");
        let machines = self.machines("");
        let machines = machines.to_str().unwrap().trim_end_matches('/');
        log.lines()
            .map(|line| line.replace(machines, "$M"))
            .collect()
    }

    fn running(&self, name: &str) -> bool {
        self.path("state")
            .join(format!("running-pm-machine-{name}.service"))
            .exists()
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

/// The file the host's image became, in the machines' templates.
fn template_file(host: &Host) -> String {
    fs::read_dir(host.machines("templates"))
        .unwrap()
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .find(|name| name.starts_with("guest-") && name.ends_with(".raw"))
        .expect("the template is installed")
}

#[test]
fn the_first_machine_copies_the_template_in_and_the_second_reuses_it() {
    let host = Host::new();
    assert!(host.create("work").status.success());
    let template = template_file(&host);
    assert_eq!(
        host.calls(),
        [format!(
            "qemu-img create -q -f qcow2 -F raw -b $M/templates/{template} $M/work/disk.qcow2 \
             34359738368"
        )]
    );
    // A read-only copy of the image, and the machine beside it.
    let copy = host.machines("templates").join(&template);
    assert_eq!(fs::read(&copy).unwrap(), [0u8; 4096]);
    assert_eq!(copy.metadata().unwrap().permissions().mode() & 0o777, 0o444);
    let record = read_to_string(host.machines("work/machine.json")).unwrap();
    assert!(record.contains("\"label\": \"blue\""), "{record}");
    let conf = read_to_string(host.machines("work.conf")).unwrap();
    assert!(conf.contains("network='virbr0'"), "{conf}");
    assert_eq!(
        host.machines("").metadata().unwrap().permissions().mode() & 0o777,
        0o700,
        "nobody else reads a person's machines"
    );

    assert!(host.create("personal").status.success());
    assert_eq!(host.calls().len(), 1);
    assert!(host.machines("personal/machine.json").exists());
    // The two machines have addresses of their own.
    let address = |name: &str| {
        let record = read_to_string(host.machines(&format!("{name}/machine.json"))).unwrap();
        record
            .lines()
            .find(|line| line.contains("\"cid\""))
            .unwrap()
            .to_owned()
    };
    assert_ne!(address("work"), address("personal"));
}

#[test]
fn a_failed_disk_takes_the_new_template_and_folder_back() {
    let host = Host::new();
    let output = host.pm(
        &[
            "machine",
            "create",
            "work",
            "--image",
            host.path("Guest.img").to_str().unwrap(),
        ],
        Some("qemu-img"),
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("make the disk of the machine work"),
        "{stderr}"
    );
    let left: Vec<_> = fs::read_dir(host.machines("templates"))
        .unwrap()
        .chain(
            fs::read_dir(host.machines(""))
                .unwrap()
                .filter(|entry| entry.as_ref().unwrap().file_name() != "templates"),
        )
        .collect();
    assert!(left.is_empty(), "nothing stays behind: {left:?}");
}

#[test]
fn a_machine_that_exists_already_is_left_as_it_was() {
    let host = Host::new();
    assert!(host.create("work").status.success());
    write(host.machines("work/disk.qcow2"), "what work did").unwrap();
    host.calls();
    assert!(!host.create("work").status.success());
    assert!(host.calls().is_empty(), "nothing was run");
    assert_eq!(
        read_to_string(host.machines("work/disk.qcow2")).unwrap(),
        "what work did"
    );
    assert!(host.machines("work.conf").exists());
}

#[test]
fn start_stop_and_remove_follow_the_machine_state() {
    let host = Host::new();
    assert!(host.create("work").status.success());
    host.calls();

    // Root's machines are the system's, everyone else's their own.
    let root = fs::metadata("/proc/self").is_ok_and(|me| me.uid() == 0);
    let user = if root { "" } else { "--user " };
    host.ok(&["machine", "start", "work"]);
    assert!(host.running("work"));
    host.ok(&["machine", "start", "work"]);
    let running = format!("systemctl {user}--quiet is-active pm-machine-work.service");
    let stop = format!("systemctl {user}stop pm-machine-work.service");
    assert_eq!(
        host.calls(),
        [
            running.clone(),
            format!(
                "systemd-run {user}--unit=pm-machine-work.service --description=The machine work \
                 --collect --quiet --property=Type=forking --property PIDFile=$M/work/work.pid \
                 quickemu --vm $M/work.conf"
            ),
            // Running already: asked, and left alone.
            running.clone(),
        ]
    );

    host.ok(&["machine", "stop", "work"]);
    host.ok(&["machine", "kill", "work"]);
    assert_eq!(
        host.calls(),
        [
            running.clone(),
            "quickemu --vm $M/work.conf --monitor-cmd system_powerdown".into(),
            running.clone(),
            stop.clone(),
        ]
    );
    assert!(!host.running("work"));

    host.ok(&["machine", "start", "work"]);
    let listed = host.ok(&["machine", "list"]);
    assert!(listed.contains("work\n"), "{listed}");
    assert!(listed.contains("pm-machine-work.service"), "{listed}");
    assert!(!listed.contains("templates"), "{listed}");
    host.calls();

    host.ok(&["machine", "remove", "work"]);
    assert_eq!(host.calls(), [running, stop]);
    assert!(!host.machines("work").exists());
    assert!(!host.machines("work.conf").exists());
    // The template stays for the next machine.
    template_file(&host);
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
    // on, so pm stops before asking anything of the plugin.
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
    // Windows 11's least: 64 GiB of disk, with nothing under it.
    assert_eq!(
        host.calls(),
        ["qemu-img create -q -f qcow2 $M/win/disk.qcow2 68719476736"]
    );
    let cds = || -> Vec<String> {
        let mut cds: Vec<String> = fs::read_dir(host.machines("cds"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        cds.sort();
        cds
    };
    let installed = cds();
    assert_eq!(installed.len(), 2, "{installed:?}");
    assert!(installed[0].starts_with("win11-"), "{installed:?}");
    assert!(installed[1].starts_with("windows-tools-"), "{installed:?}");
    let conf = read_to_string(host.machines("win.conf")).unwrap();
    for expected in [
        "ram='4096M'",
        "guest_os='windows'",
        "tpm='on'",
        "iso='",
        "fixed_iso='",
    ] {
        assert!(conf.contains(expected), "{expected} in\n{conf}");
    }
    let record = read_to_string(host.machines("win/machine.json")).unwrap();
    assert!(record.contains("\"system\": \"windows\""), "{record}");
    assert!(record.contains("\"label\": \"red\""), "{record}");

    // A second machine from the same CDs copies neither again, and removing
    // one leaves them for the other.
    let mut second = args;
    second[2] = "win2";
    host.ok(&second);
    host.ok(&["machine", "remove", "win"]);
    assert!(host.machines("win2.conf").exists());
    assert_eq!(cds(), installed);
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
    fs::remove_file(host.path("plugins/quickemu.wasm")).unwrap();
    let output = host.pm(&["machine", "list"], None);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no plugin manages machines"), "{stderr}");
}

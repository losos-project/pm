# pm

Build signed recipes into `.cpkg` archives and run their entrypoints in a Linux
sandbox. See [the examples](examples/README.md) for `.rhai` recipe syntax and signing.

## Recipes are Rhai

Recipes are [Rhai](https://rhai.rs) scripts in `*.rhai` files that call
`package(#{ ... })` once, with `step(...)` for each build step. Rhai has no
keyword arguments, so `package` takes an object map. Loops, functions and
conditionals generate steps and commands; evaluation is hermetic (no I/O, no
clock, no `import` or `eval`), runs under operation and size limits so a
runaway loop is an error rather than a hang, and happens before the policy is
derived and before anything runs.

```rhai
package(#{
    name: "hello",
    version: "1.0.0",
    steps: [
        step(Install, "stage", ["install -Dm755 /usr/bin/echo /dest/usr/bin/hello"]),
    ],
});
```

* `pm generate build.rhai` writes a starter file.
* `pm-lsp` is a language server (diagnostics, completion, hover) for `.rhai`
  recipes, and [`editors/`](editors/README.md) has Zed and Neovim integrations
  that use it. `pm-lsp --definitions` prints a Rhai definitions file for editors
  that run a Rhai language server of their own.

### Objects

`step(...)`, `kernel(...)` and `Package(name, version)` return objects with
properties and methods, so a package can be built up before it is declared.
Recipes can also define their own objects as object maps with closures, where
`this` is the map:

```rhai
let autotools = #{
    prefix: "/usr",
    build: |name| step(Build, name, [`./configure --prefix=${this.prefix}`, "make"]),
};

let p = Package("hello", "1.0.0");
p += autotools.build("compile");
p += step(Install, "stage", []).push("make install DESTDIR=/dest");
p.depends_on("../libc/build.rhai");
package(p);
```

`Step` has `stage`, `name`, `run` and `dl_urls`, plus `push(command)`,
`download(url, sha256)` and `+= command`. `Package` has `name`, `version`,
`dependencies`, `steps` and `kernel`, plus `depends_on`, `add_step`,
`add_steps`, `with_kernel`, `+= step` and `for step in package`. Setting a
property is checked on the spot, so `s.stage = "Deploy"` fails on that line.

### Plugins in recipes

An installed plugin is a Rhai module under its own name. Its symbols are
constants and, when it is built against the `recipe-plugin` world, its recipe
functions are functions that return pm's own types, checked as if the recipe
had built them:

```rhai
let p = Package("units", "1");
p += systemd::install_unit("units/foo.service");   // a Step
p += step(Test, "unitdir", [`test -d /dest${systemd::unitdir}`]);
package(p);
```

`pm plugins` lists what each plugin adds. See
[`plugins/README.md`](plugins/README.md#recipe-functions).

### How recipes run

Recipes are compiled with Rhai's full optimiser (constant folding and inlining
of pure calls) and fast operators, lowered to bytecode and run on Rhai's Grain
VM. The engine is built once per thread, so a dependency graph of many recipes
pays for it once. Strict variables and strict map properties catch misspellings
before anything runs.

Some Rhai features are deliberately left out: floating point (`no_float`; a
package has no use for it and it makes evaluation platform-dependent), the
clock (`no_time`), `import` and `eval` (a signature covers one file as
written), the `unchecked` build (it removes the operation and size limits),
and an on-disk bytecode cache (the bytes that run would no longer be the bytes
that were signed).

### Moving off Starlark and YAML

Recipes used to be Starlark `.package` files, and before that YAML. Both still
load, so nothing breaks today, but each load logs a deprecation warning and
support will be removed in a future release.

* `pm migrate build.package` writes `build.rhai` next to it, describing the same
  package. `pm migrate build.yaml` does the same for YAML. `-r` also converts
  every Starlark or YAML recipe it depends on and points the dependency paths at
  the new files; `--stdout` prints instead of writing.
* The Starlark is evaluated, not translated, so loops and functions come out as
  the steps they produced, written out literally. Comments are not carried over.
* A signature covers one file's bytes, so sign the new file with `pm sign`.
* The old file is left in place. Delete it, and its `.sig`, once the `.rhai`
  file is signed and builds.

## Shipping a kernel

A package can ship its own Linux kernel. Install the image into `DESTDIR` with
the package's steps and name it in `package(#{ ... })`:

```rhai
package(#{
    name: "hello",
    version: "1.0.0",
    steps: [
        step(Install, "stage", [
            "install -Dm644 /path/to/vmlinuz /dest/boot/vmlinuz",
            "install -Dm755 /path/to/hello /dest/usr/bin/hello",
        ]),
    ],
    kernel: kernel("boot/vmlinuz", "mitigations=off"),
});
```

`image` is relative to `DESTDIR`. The build fails if the steps did not install
it or if it is not a Linux kernel image (a bzImage, a vmlinux, or an arm64 or
RISC-V `Image`), and the image is never offered as a program. `cmdline` is
optional and goes on the kernel command line ahead of the parameters pm relies
on (`console`, `panic`, `rdinit`), so it cannot override them; `init=` and
`rdinit=` are refused.

`pm run` boots such a package's kernel in a QEMU virtual machine instead of
running it in the namespace jail on the host's kernel:

* The guest's root filesystem is an initramfs pm assembles for each run. It
  holds the package at `/pkg`, the host loader and shared libraries the
  package's binaries link (at their host paths), and `pm-vm-init`, which runs
  the entrypoint, reports its exit code to the host and powers the machine off.
  Nothing else from the host is visible, the machine has no network device and
  no disk, and the recorded landlock profile is not applied inside it.
* The console is your terminal, so the program's output and input work as they
  do in the jail. Its exit code is `pm run`'s exit code.
* It needs `qemu-system-x86_64` on `PATH`, and uses KVM when `/dev/kvm` is
  usable (emulation otherwise, which is slow). Only x86-64 hosts can boot a
  package kernel today.
* An installed plugin may start the machine instead: the `libvirt` plugin
  (`plugins/libvirt/`) hands it to libvirt through `virsh`, so it runs as a
  transient domain at libvirt's default URI, shows up in `virsh list` and
  virt-manager, and stops with `pm run`. `pm run --qemu` skips plugins and
  starts QEMU directly. See "Starting virtual machines" in
  `plugins/README.md`.
* The kernel needs initramfs support, an 8250/16550 serial console and ELF
  support built in, which distribution `generic` and `virtual` kernels have.
* `--network` and `--audit` are refused, because the guest has no NIC and a
  traced host process cannot see into a VM. `pm run --host-kernel` runs the
  package in the usual jail and ignores its kernel.

Install `pm-vm-init` beside `pm`: it is copied into every initramfs, and is
much smaller than `pm`, which is used in its place when it is missing.

## Machines

`pm machine` keeps virtual machines that outlive any one command: each is made
from a *template*, a disk image, and gets a copy-on-write disk of its own on top
of it, so any number of machines share one template's space. They are yours, as
your files are: kept under `$XDG_DATA_HOME/pm/machines`, readable by you alone,
and run as you.

```sh
pm machine create work --image guest.qcow2 --label blue   # left stopped
pm machine start work
pm machine list
pm machine stop work        # asks the guest to shut down
pm machine kill work        # pulls the plug
pm machine remove work      # the machine and its disk; the template stays
```

A template is the image's bytes: pm reads the image once for its SHA-256, and the
same name with different bytes is a new template beside the old one, so the
machines made from the old one keep their base. `--image` takes raw and qcow2;
the disk is never smaller than the template's. `--label` is the colour a desktop
frames the machine's windows in (red, orange, yellow, green, gray, blue, purple
or black); `--memory`, `--cpus`, `--disk` and `--firmware` (uefi, the default,
or bios) size and boot it.

A machine can instead start empty and install its system from CDs:

```sh
pm machine create win --installer Win11.iso --system windows --label red
pm machine create fedora --installer Fedora-Workstation-Live.iso
```

Each `--installer` is a CD, installed once and shared like a template; the
machine boots its disk first and the first CD while the disk has nothing to
boot, so the installer runs once and the system it installed starts after. It
has a screen, for the installer and for a system that cannot send its windows
to the desktop, which a SPICE viewer shows. `--system`
(linux, the default, or windows) also gives it the host's CD of tools for that
system, the first `pm/machines/<system>-tools.iso` under `$XDG_DATA_DIRS`, or
the one `--tools` names: what a host puts there is what fits a guest to its
desktop. Windows cannot install without one, since Setup has no driver for a
virtio disk, and its machine is what Windows 11 asks of a PC: UEFI, a TPM 2.0,
Hyper-V's enlightenments under KVM, its clock in local time, 4096 MiB and
64 GiB unless told otherwise, and x86-64 only.

pm does none of this itself. The first installed plugin built against the
`machine-plugin` world turns each request into steps and pm runs them, held to
the programs the plugin listed at load - see "Managing machines" in
`plugins/README.md`. The `quickemu` plugin (`plugins/quickemu/`) makes them
quickemu's: the template is copied in read-only under `templates/`, the machine
is a `<name>.conf` quickemu reads and a folder holding its disk and pm's record of
it, `machine.json`, with its label, its vsock address (not for Windows) and what
it was made from; a CD is copied in under `cds/`. A machine runs as the service
`pm-machine-<name>` of your own service manager, on the host's `virbr0` bridge
when it has one, with QEMU's guest agent and its screen on sockets in its
folder. The `libvirt` plugin (`plugins/libvirt/`) makes them libvirt's
instead: domains of the daemon at libvirt's default URI, their disks in its
`default` storage pool, on its `default` network, so virsh and virt-manager see
the machines pm made, and every user who may manage that daemon sees the same
ones. On a host with a GPU, a machine made from a template gets one of its own,
VirGL's, rendering on the host's first render node, which pm finds and passes
in. With both installed, `libvirt` answers, being first by file name. Names
are 1-32 characters of `a-z`, `0-9` and `-`, starting with a letter, checked
before any plugin sees them.

## Administering the machine

`pm system` is how an administrator changes the system without becoming root:

```sh
pm system restart sshd            # start, stop, restart or reload a unit
pm system update --reboot         # install the newest system and boot it
```

None of it runs as the caller, and none of it is setuid. `pm` asks `pmd --system`,
a service on the system bus that runs as its own `pm` user, and the daemon asks
polkit whether the caller may, letting polkit ask them to authenticate as an
administrator: through the desktop's agent, or `pkttyagent` on the terminal when
there is none. Only then does it act, as `pm`, through systemd.

That is all it does: it runs no command of the caller's, as root or otherwise,
and opens no shell. An administrator's session, or whatever takes it over, can
start and stop the units the system already has and install its updates, and
nothing more.

| Action | Asked for | Default |
| --- | --- | --- |
| `org.pm1.system.manage-units` | start, stop, restart, reload | an administrator, kept a while |
| `org.pm1.system.update` | update | an administrator, kept a while |

A distribution installs what the daemon needs from `data/`: the D-Bus policy that
lets only `pm` own `org.pm1.System`, the activation file that hands the bus over
to `pm-system.service`, and the polkit actions, which name `pm` as their owner so
an unprivileged daemon may ask polkit about other people. It supplies the rest
itself: the `pm` user, `pm-system.service` running `pmd --system` as that user,
and a polkit rule letting `pm` manage units, all but any unit that is a root
shell by another name, such as `debug-shell.service`. That rule makes `pm` as trusted as root, as run0 was,
so a distribution that gives it should keep anyone else from managing units
directly, or `pm system` is only one way in of several.

## Containers

`pm container` runs your own containers, as you, from compose files:

```sh
pm container up compose.yml      # make and start what it describes
pm container create compose.yml  # make it, left stopped
pm container list
pm container status web          # created, running, paused, exited
pm container ports web
pm container stop web            # also start, pause, unpause
pm container remove web
pm container down compose.yml    # stop and remove what it describes
pm container version
```

Root has none: a container of root's would run with the whole system's
privilege, so root's requests are refused. As with machines, pm does none of it
itself. The first installed plugin built against the `container-plugin` world
turns each request into steps and pm runs them, held to the programs the plugin
listed - see "Managing containers" in `plugins/README.md`. The `podman` plugin
(`plugins/podman/`) makes them rootless Podman's, with podman-compose for compose
files: no daemon, and the containers, their images and their state in your
home. Names are 1-64 characters of letters, digits, `_`, `.` and `-`, starting
with a letter or a digit, and a compose file must exist; both are checked before
any plugin sees them.

## Integration with distribution build tools

Projects such as `dichhead/losos-desktop` generate recipes and assemble system
images from their outputs. Use these interfaces instead of duplicating pm's
internal download hashing or parsing its human-readable policy table.

### Locate a source download

```sh
pm source-path 'https://example.org/project-1.0.tar.xz'
pm source-path --relative 'https://example.org/project-1.0.tar.xz'
```

The first command prints the source's absolute path inside the build jail
(`/build/.../project-1.0.tar.xz`). The second prints a path relative to the build
working directory, useful for unconfined builds. Both print only one path to
stdout, perform no downloads, create no files and load no plugins. Use exactly
the URL in the recipe's `dl_urls` map, including its query string. URLs without a
usable filename fail with a nonzero exit status.

Rust consumers can use `pm::step::Step::download_path(&url)`. The downloader uses
this same function; consumers should not depend on the digest algorithm. Resolve
paths with the pm version that will build the generated recipe. Hash verification
still happens during the build, not during a path query.

### Machine-readable policy gates

```sh
pm explain build.yaml --format yaml
pm explain build.yaml --format yaml --permissive
```

YAML output is a single document on stdout; diagnostics stay on stderr. It
contains:

| Field | Meaning |
| --- | --- |
| `schema_version` | Currently `1`; reject unsupported versions in consumers. |
| `name`, `version`, `dependencies` | Package name, version components and declared dependency recipe paths. |
| `fingerprint` | The same policy change-detection digest as the text report, not a cryptographic signature. |
| `capabilities` | Sorted capability names, including `Network` when granted. |
| `commands` | Ordered records with `command`, `fingerprint` and boolean `matched`. |
| `plugins` | Loaded plugin `name`, `version`, `sha256` and `trust`. |
| `symbols` | Referenced plugin symbols mapped to their expanded values. |
| `downloads` | Records with `step`, `url`, expected `sha256` and in-jail `path`, sorted by URL within each step. |

The report covers the specified recipe, **not its dependency closure**. It
expands symbols and derives policy without running build commands or fetching
sources. Signature verification and plugin trust rules are identical to text
mode. Existing text output remains the default.

Always check the process exit status, even when stdout contains a valid report.
With `--permissive`, unmatched commands are included with `matched: false`, but
the command still exits nonzero. Without it, policy derivation fails before a
report is emitted. Missing/untrusted recipes and unusable plugins also fail.

### Desktop payloads and current limits

Regular files are binary entrypoints only when at least one Unix executable bit
is set. Libraries (`.a`, `.so`, `.so.N`) remain library entrypoints without
executable bits. Non-executable systemd units, desktop entries, icons, headers
and configuration files remain in the archive but are not offered as programs.

pm is not yet a system package installer or image composer. Dependencies are
bundled as nested archives, not automatically merged into a build sysroot or
runtime root. An image builder must preserve the complete required payload
(including `/etc` and `/var`, not only `/usr`), handle file conflicts and symlinks,
and keep build-only pkg-config prefix rewrites out of the final image. Service
activation, sysusers, presets, architecture-aware image manifests and transactional
system updates remain the distribution's responsibility. These interfaces do not
make `pm run` a replacement for systemd service management.

## Releases

Every push to `master` that passes `ci` is published as a GitHub prerelease,
`nightly-<YYYYMMDD>T<HHMM>` after the commit's time in UTC, with pm's
x86_64 binaries named for its version and a `SHA256SUMS`. Every day at 02:17
UTC `release.yml` also cuts a `weekly-`, `monthly-` or `yearly-` release from
the newest nightly when that cadence has none yet this ISO week, month or
year: the same commit and files under the cadence's tag. Only a yearly release
becomes GitHub's latest. These are the cadences the OS releases on ([Release
cadences](https://github.com/losos-project/desktop/blob/main/docs/releases.md#release-cadences)),
and a tag is the version to pin pm at. Each release is named with an
adjective and a verb that share a letter, from Oxford's word lists, and none
is edited once published (`.github/release`). A `v*` tag pushed by hand is
still released under its own name.

`lockfiles.yml` moves every lockfile to what its manifest allows each Monday
at 03:00 UTC, in one commit pushed straight to the default branch, where
CI checks it as any other push.

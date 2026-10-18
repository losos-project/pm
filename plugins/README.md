# Writing a pm plugin

A pm plugin is a **WebAssembly component**. pm loads every `*.wasm` in
`$XDG_CONFIG_HOME/pm/plugins/` (or `$HOME/.config/pm/plugins/`) and calls it to
answer the two questions its own built-in tables cannot always answer:

| hook               | question                                                                  | what pm does without it                        |
|--------------------|---------------------------------------------------------------------------|------------------------------------------------|
| `classify-command` | what does this build-step command need from the build jail?               | refuses to build, naming the command           |
| `scan-source`      | what does this source file imply the built program needs at run time?     | contributes nothing for file types it cannot parse |

pm's own answers are plugins too. `bundled/` holds one component per ecosystem
(`buildsys`, `rust`, `go`, `node`, `python`, `c`, `posix`, `git`) carrying its
build-command fingerprints, and one tree-sitter scanner per language (`c-source`,
`cpp-source`, `rust-source`, `python-source`, `go-source`, `bash-source`) carrying
the grammar and its queries. They are written against the same `wit/plugin.wit`
(the `bundled` world adds one export listing the fingerprint names). pm's own
`build.rs` compiles and encodes them on every build of pm and embeds them in the
binary, so building pm needs the `wasm32-unknown-unknown` and `wasm32-wasip2` targets
and clang (for the C grammars); pm runs them in the same runtime as yours. They are consulted first, in that order, and recorded
under their own names exactly as the old compiled-in tables were; the plugins
described here only ever hear about what none of them recognised.

Two things differ for the bundled tier, because it ships with pm rather than
being installed next to it: its instances are reused across calls on a thread
(so each grammar's queries compile once, not once per file), and its fuel and
memory budgets are sized for parsing whole source files. Neither applies to an
installed plugin.

The interface is `wit/plugin.wit` at the repository root. Read it first; it is
the contract, and it is commented.

## The sandbox

A plugin runs **inside pm's own process**. There is no jail around it, because
pm is the thing doing the jailing, so the WebAssembly sandbox is the entire
boundary. What that boundary is:

* **One import.** `pm:plugin/host.log`, which takes a level and a string and
  returns nothing. That is the whole host surface. There is **no WASI**: no
  files, no clock, no randomness, no network, no environment, no arguments, no
  `proc_exit`. A component that imports anything else does not instantiate.
* **A fuel budget per call.** Fuel counts executed instructions, so it bounds
  work rather than time, and it is deterministic - the same call on the same
  input traps at the same instruction on every machine. A plugin cannot hang a
  build.
* **A memory cap, a table cap and a stack cap.**
* **A fresh instance per call.** Nothing carries between calls: one build file's
  commands cannot influence how the next is classified, and one source file
  cannot influence the grants derived from another.

Because `log` returns nothing, no information flows *into* a plugin through it.
A plugin's answer is a function of its own bytes and its argument, and of
nothing else - which is what lets pm fold the plugin set into a build policy's
digest and have that mean something.

## What a plugin may and may not change

* It is **only asked about commands pm's own table did not match**. No plugin
  can decide that `cargo` needs no network or that `git` is not version
  control, because no plugin is ever asked.
* It **publishes a ceiling** in its manifest, and pm drops any capability a
  verdict asks for outside it. The ceiling is the plugin's own claim, enforced;
  its value is that reading `pm plugins` is a cheap substitute for reading the
  plugin. It is not a defence against a key you should not have trusted.
* Its fingerprints are recorded as `<plugin>:<name>`, so `pm explain` shows who
  classified what. Its run-time grants carry `plugin` provenance and an
  evidence line naming it, so `pm profile` shows who asked for what.
* Its grants land in a profile recorded in **audit mode**, exactly like pm's
  own signals. Nothing on the build path turns enforcement on.
* A plugin that traps, runs out of fuel or answers with something unusable is
  logged and treated as having had no answer. It cannot fail a build to spite
  you.

## Symbols: values a build file can use

Beside the two hooks, a plugin publishes **symbols** — named constants a build file
substitutes into a step command as `%{<plugin>:<name>}`:

```yaml
run:
  - install -Dm644 demo.service %{systemd:unitdir}/demo.service
  - install -Dm644 demo.conf %{systemd:tmpfilesdir}/demo.conf
```

The point is what a build file would otherwise hardcode and get wrong. Where unit
files go is a fact about systemd, not about your package, and digging it out of
`pkg-config --variable=systemdsystemunitdir systemd` needs pkg-config *and* systemd's
development files inside the build jail to answer. `pm plugins` prints every symbol
every installed plugin offers.

They are constants, not computed values: a plugin has no filesystem, no environment and
no clock, so there is nothing to compute one *from*. The list is fixed in the component
and pm reads it once, at load, which is also what makes it reviewable.

### What a symbol may and may not do to a command

A symbol changes **what command runs**, which is a larger power than anything else a
plugin has — classification only decides what a command may reach. Two rules bound it,
and between them a symbol can do exactly one thing: fill in part of an argument the
build file already wrote out.

- **A value is one word.** Commands are split on whitespace and handed to `execve` with
  no shell in between, so a value containing whitespace would not fill an argument in,
  it would *add* arguments. pm drops any value holding whitespace, a control character
  or a NUL at load, and a build file naming a dropped symbol then fails loudly.
- **A symbol may not be the program.** A reference in a command's first word is refused.
  The first word is what the fingerprint table classifies and what the jail resolves and
  execs; a plugin choosing that is a different power from a plugin describing it.

And it cannot hide. Expansion happens *after* the build file's signature is checked and
*before* the policy is derived, so the jail is always sized for the command that runs,
`pm explain` prints both the expanded commands and the symbols that shaped them, and
the expanded text feeds the policy digest. The author signed `%{systemd:unitdir}`, not
whatever that is today — the effective command is the product of two separately signed
things, the build file and the plugin, and neither alone decides it.

### What is and is not a reference

`%{…}` is a reference **only** when what is inside is a well-formed `plugin:symbol` —
a plugin name, one colon, a symbol name, both lower-case. A well-formed reference that
names nothing is an error, so a mistyped `%{systemd:unitdirr}` fails rather than
installing into a directory named after the typo.

Anything else keeps its shape: `%{NAME}` has no colon, `printf %s` and `100%%` have no
brace. There is no escape character because there is nothing to escape — a string that
is not shaped like a reference is already literal. The one cost is that a command cannot
contain a literal `%{` that *is* shaped like a reference.

Symbols are not substituted into `dl_urls`. A download's identity is its URL and its
hash, both of which the build file states; and `%` already means something in a URL.

## Recipe functions

A plugin built against the **`recipe-plugin`** world, rather than `plugin`, also
adds functions to Rhai recipes. It exports everything a plugin does, plus:

```wit
export recipe-functions: func() -> list<recipe-function>;
export call-recipe-function: func(name: string, args: list<string>) -> result<string, string>;
```

`recipe-functions` is called once, at load, like `describe`. Each entry names a
function, its parameters (their number is its arity), what it returns and a line
of documentation. A recipe calls it as `<plugin>::<name>(...)`, with any `-` in
the plugin's name written `_`; the plugin's symbols are constants in the same
module.

Arguments arrive as one JSON text each, a `Step`, `Kernel` or `Package` as the
object map it stands for. The answer is JSON too, of the kind `returns` names:
`any` (plain data; no floating point, since recipes have none), `step`, `steps`,
`kernel` or `package`. pm checks a typed answer exactly as it checks what a
recipe writes, so a step with a misspelt key or an unknown stage fails the
recipe at the call. An `err` fails it with the plugin's message.

A call runs like a hook: in a fresh instance, metered, with only `log`. The
answer is therefore a function of the arguments alone, so a recipe that calls
a plugin still evaluates to the same package wherever the same plugin is
installed, and the plugin's file hash is already part of the policy digest.
Names must be `[a-z0-9_]`, at most 32 characters and not a Rhai keyword; at
most six parameters; a plugin built against plain `plugin` loads exactly as
before. The `systemd` plugin here adds `install_unit(file)` and
`install_units(files)`; see its source.

## Starting virtual machines

A plugin built against the **`vm-plugin`** world starts the virtual machine a
package that ships its own kernel boots in, instead of pm starting QEMU itself.
It exports everything a plugin does, plus:

```wit
export launchers: func() -> list<string>;
export launch-machine: func(machine: machine) -> result<option<launch>, string>;
```

`launchers` is called once, at load, and names every program the plugin may
have pm run: bare names, found on `PATH`, at most twelve. `pm plugins` prints
them, and a launch naming anything else is refused, so that line is the most a
plugin can ever start. This is the only world whose answer makes pm run
anything.

`launch-machine` gets the machine pm laid out: its name and title, its
directory, the kernel, the initramfs, the command line, memory, CPUs, whether
KVM is usable, and the Unix socket init reports the entrypoint's exit on. It
answers with a program, its arguments and files to write into the directory (a
domain definition, say), or `none` to leave the machine to the next plugin and
in the end to pm's own QEMU. An `err` fails the boot with the plugin's message
rather than quietly booting under different hands. pm then holds the program
to one contract:

* It lives exactly as long as the machine. pm waits for it, and sends it
  `SIGTERM` if pm dies first.
* It owns the console: pm's terminal, or a pseudo-terminal pm copies when
  stdin or stdout is not one.
* The guest's second serial port connects to the status socket. Init's report
  there, not the program's exit status, is what `pm run` returns.

The directory is searchable but not listable and every file in it is private
to its owner, because the program may run QEMU as another user: whoever does
has to be handed each file, which is what libvirt does. `libvirt/` is the
example: one launcher, `virsh`, and a transient domain started with
`virsh create --console --autodestroy`. `pm run --qemu` asks no plugin.

## Managing machines

A plugin built against the **`machine-plugin`** world manages the host's
persistent virtual machines for `pm machine`. It is a `vm-plugin` - the same
`launchers`, printed by `pm plugins` with `machines: yes` - plus one call:

```wit
export machine-plan: func(request: machine-request, place: machine-place) -> result<list<machine-step>, string>;
```

Every user has machines of their own. The place says where the user pm runs as
keeps them, `pm/machines` under `$XDG_DATA_HOME`, which pm has made private to
them; whether they run under that user's own service manager (everyone's but
root's); and 32 random bytes fresh for the request, for what has to differ from
one machine to the next, since a plugin has no randomness of its own. A plugin
that still exports the old `machine-steps`, which had no place, is not asked.

A request is `create(machine-spec)`, `list`, or `start`, `stop`, `kill` or
`remove` of a machine by name; the spec carries the name, the label, its
source, the disk size, memory, CPUs, whether the host has KVM and its
architecture. The source is a template (its name, digest, image path, format,
file and disk sizes, firmware) or an installer: the system it installs, linux
or windows, and its CDs (name, digest, image path and file size each), the
host's CD of tools for that system last when there is one. The
answer is the steps that carry the request out. Each step is a launch, held to
`launchers` like a machine's, with three optional launches beside it:

* `when` - run the step only if this exits successfully;
* `unless` - skip the step if this exits successfully;
* `undo` - how to take the step back.

pm runs every condition first, before any step, so the plan is fixed by the state
the host was in when the request was made, and a question asked by several steps
is asked once. The steps then run in order with pm's standard output and error,
each in a directory of its own private to the user holding the files it asked
for, which its arguments name by their bare names. The first failure stops the
request and runs the `undo` of every step that had finished, newest first; not
the failed step's, which is taken to have changed nothing. Only the first plugin
that manages machines is asked: every request about a machine has to reach the
hypervisor that made it.

`quickemu/` is the example. Its steps check no machine has the name, copy the
template in read-only under `templates/` unless it is there (`cp` to a `.part`,
`chmod`, `mv`, all skipped together), make the machine's folder and its qcow2
disk on top of the template, and write the machine's `<name>.conf` and
`machine.json`. An installer's CDs are copied in the same way, each on its own,
and its disk starts empty. `start` runs `quickemu --vm` in a service of its own
(`systemd-run`), `stop` has quickemu ask the guest to shut down, `kill` stops
the service, and `remove` stops it if it runs and deletes the machine's folder
and `.conf`, leaving the template and the CDs other machines may share.
`libvirt/`, which managed machines as libvirt domains before, now only boots
packages' kernels.

## Managing containers

A plugin built against the **`container-plugin`** world runs the containers of
the user pm runs as, for `pm container`. It is a `vm-plugin` - `launchers`
again, printed by `pm plugins` with `containers: yes` - plus one call:

```wit
export container-plan: func(request: container-request, place: container-place) -> result<list<machine-step>, string>;
```

The place says whether that user is anyone but root. A request is `list`,
`version`, `up`, `create` or `down` of a compose file by its absolute path, or
`status`, `ports`, `start`, `stop`, `pause`, `unpause` or `remove` of a
container by name; pm checks the name and that the file exists before asking.
The answer is steps, the same `machine-step`s a machine plugin answers with,
and pm runs them the same way: conditions first, then the steps in order with
pm's standard output and error, undoing what finished when one fails. What a
step prints is the answer to `list`, `status`, `ports` and `version`. Only the
first plugin that manages containers is asked.

`podman/` is the example, and refuses root. Each request is one step: Podman's
own command (`ps`, `inspect`, `port`, `container start` and so on, the name
after `--`) or podman-compose's for a compose file, `version` both programs'
`--version`.

## Trust

**A plugin must be signed**, by a key in the same trust store that governs build
files, or pm refuses to load it:

```sh
pm sign  ~/.config/pm/plugins/zig.wasm         # writes zig.wasm.sig
pm trust <the signer's public key hex>         # once, per key
```

`--allow-unsigned-plugins` skips the check. It is for a plugin you are writing
and have not signed yet. A build file names commands that run inside a jail; a
plugin *is* code that runs inside pm and helps decide what that jail allows, so
the escape hatch gives up rather more here than it does there.

`--no-plugins` loads no installed plugin at all, which is the honest way to find
out whether one of them is responsible for a surprising policy. It does not turn
off the bundled plugins: they are pm's own fingerprints and scanners, and a policy
derived without them would not be pm's.

## Building one

The crates here are a separate cargo workspace, so `cargo build` at the
repository root never drags a `wasm32` target in.

```sh
rustup target add wasm32-unknown-unknown wasm32-wasip2
./build.sh              # everything, into dist/
./build.sh zig          # just one
```

Two steps happen inside: `cargo build --target wasm32-unknown-unknown` produces
a **core module**, and then `encoder/` wraps it into a component.
`wasm-tools component new` does the same job if you have it installed;
`encoder/` exists so `build.sh` needs nothing but a Rust toolchain.

A plugin of your own, in outline:

```toml
# Cargo.toml
[lib]
crate-type = ["cdylib"]

[dependencies]
wit-bindgen = { version = "0.51", default-features = false, features = ["macros", "realloc"] }
```

```rust
wit_bindgen::generate!({ path: "path/to/pm/wit", world: "plugin" });

use pm::plugin::types::{Capability, Hook};

struct MyPlugin;

impl Guest for MyPlugin {
    fn describe() -> Manifest { /* name, version, summary, hooks, ceiling, extensions, symbols */ }
    fn classify_command(command: String) -> Option<Verdict> { /* ... */ }
    fn scan_source(file: SourceFile) -> Vec<Grant> { /* ... */ }
}

export!(MyPlugin);
```

Both exports are mandatory - the component model has no optional export - but
pm calls a hook only when `describe` lists it, so the one you do not implement
returns `None` or an empty `Vec`.

`Manifest`, `Verdict`, `Grant` and `SourceFile` are re-exported into the crate
root because the world's own functions name them; `Capability`, `Permission`,
`Hook` and `Symbol` are reached through `pm::plugin::types`.

Any language with a component toolchain works. Nothing about the interface is
Rust-specific; Rust is simply what these examples are written in.

## What is here

| crate         | what it is                                                                |
|---------------|---------------------------------------------------------------------------|
| `zig/`        | classifies `zig` commands and reads `.zig` sources                        |
| `systemd/`    | classifies systemd tooling, reads unit files, publishes the install dirs  |
| `sysupdate/`  | classifies `systemd-sysupdate` and reads its transfer definitions         |
| `sysext/`     | classifies the system-extension image toolchain; one hook, on purpose     |
| `libvirt/`    | boots a package's kernel through libvirt, via `virsh`                     |
| `quickemu/`   | manages each user's `pm machine`s with quickemu, as services of their own |
| `podman/`     | runs each user's `pm container`s with rootless Podman and podman-compose  |
| `unitfile/`   | the unit-file parser the three systemd plugins share - an ordinary lib    |
| `encoder/`    | core module → component, so `build.sh` needs no `cargo install`           |
| `fixtures/*`  | deliberately badly behaved plugins, for `tests/plugins.rs`                |

The fixtures are the interesting reading if you want to know what pm does when
a plugin misbehaves: `greedy` asks for more than it published, `runaway` never
returns, `nameless` cannot be attributed, `wasi` wants more of the host than pm
lends anybody, `launcher` names programs it never listed, and `scanner` contributes run-time grants from a file type pm has
no grammar for.

## Three things the systemd plugins are worth reading for

**A declaration beats a heuristic.** pm's own source analysis reads a syntax
tree looking for calls that *imply* a permission, and its module documentation
lists six things it cannot see. A `.service` unit needs none of that: it is the
author saying, in a vocabulary that lines up almost one-for-one with pm's
`Permission`, where the writes go and what gets executed. That precision buys
something a source scanner can never have - **negative** information.
`PrivateNetwork=yes` does not merely fail to suggest network access, it denies
it, so `systemd/` drops every network grant it derived from the same file. Not
finding a `socket()` call never means there is not one.

**Claim a generic extension, then gate on content.** `sysupdate/` reads `.conf`
files, an extension a source tree is full of. It looks for a `[Transfer]`
section before it records anything, and produces nothing at all for a `.conf`
belonging to something else. Any plugin claiming a generic extension should do
the same - a plausible-looking wrong grant is worse than no grant.

**Refusing is a legitimate answer.** `systemd/` recognises `systemd-nspawn`,
`systemd-run` and `machinectl` and then declines to classify them; `sysext/`
does the same for `mkosi` and `debootstrap`. Each runs something of its own
choosing, so a verdict would size a jail for a program nobody has read. pm's
answer to an unclassified command is a diagnostic naming it, and `--permissive`
is still there for a human who has decided. A plugin that classified everything
it saw would publish a ceiling wide enough to make `pm plugins` useless.

`sysext/` is also the example of a **single-hook** plugin: a `systemd-repart`
definition says how an image is assembled at build time, which is not what
`scan-source` asks about, so it declares only `classify-command` and its
`scan-source` export is never reached.

## On writing a good `scan-source`

The reference plugin matches over a token stream with comments and string
literals removed. That is the least a scanner can do to be honest, and it is
still a long way short of what pm does for the languages it knows: pm's own
queries in `src/perms/source.rs` match against a *syntax tree*, which is how
`fopen(path, "a")` becomes a write and `fopen(path, "r")` a read, decided from
the same call node rather than from what happened to be nearby.

Nothing in the plugin interface stops you doing as well. A component can carry
a whole parser - tree-sitter grammars compile to WebAssembly - and the fuel and
memory budgets are sized for a real one. The reference plugin is small because
it is an example, not because that is the ceiling.

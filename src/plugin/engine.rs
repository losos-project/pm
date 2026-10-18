//! The WebAssembly runtime a plugin is confined to.
//!
//! pm runs plugins **inside its own process**, which is the one place in this crate
//! where there is no jail, no `landlock` and no separate address space to fall back on:
//! the WebAssembly sandbox is the whole boundary. Everything in this module exists to
//! make that boundary worth trusting.
//!
//! # What a plugin is given
//!
//! One import, `pm:plugin/host.log`, which takes a level and a string and returns
//! nothing. That is the entire host surface. There is no WASI: no files, no clock, no
//! randomness, no network, no environment, no arguments, no `proc_exit`. A component
//! that imports anything else fails to instantiate, by construction rather than by
//! check - [`Runtime::linker`] only ever has `log` defined on it, and wasmtime refuses
//! an instantiation whose imports it cannot satisfy.
//!
//! Because `log` returns nothing, no information flows *into* the guest through it.
//! A plugin's answer is therefore a function of its own bytes and the argument it was
//! called with, and of nothing else - which is what lets a plugin's identity be folded
//! into the build policy digest in [`super::Registry::digest`] and mean something.
//!
//! # What a plugin is denied
//!
//! * **Time.** Every call is metered with [`FUEL`] units, and running out is a trap.
//!   Fuel counts executed instructions, so this is a hard bound on work rather than a
//!   timeout - and, unlike an epoch deadline, it is deterministic: the same call on the
//!   same input traps at the same instruction on every machine. A plugin cannot hang a
//!   build.
//! * **Memory.** [`MEMORY_BYTES`] caps linear memory and [`TABLE_ELEMENTS`] the tables,
//!   through wasmtime's [`StoreLimits`]. A growth request past the cap fails inside the
//!   guest, as an allocation failure, rather than taking the machine down with it.
//! * **Stack.** [`STACK_BYTES`] bounds recursion; past it the call traps.
//! * **Company.** One instance per store, and a fresh store per call - see
//!   [`Runtime::enter`].
//!
//! # A fresh store per call
//!
//! Each call gets a new [`Store`] and therefore a new instance with zero-initialised
//! memory. It costs an instantiation per call, which is microseconds against a
//! tree-sitter parse or a compiler invocation, and it buys the property that makes
//! plugin answers reviewable: **nothing carries between calls**. One build file's
//! commands cannot influence how the next one is classified, and one source file cannot
//! influence the grants derived from another. A plugin that wants to accumulate state
//! has nowhere to put it.
//!
//! The compiled [`Component`], which is the expensive part, is built once per plugin at
//! load time and shared across every call and every thread.

use miette::{Result, miette};
use tracing::{debug, error, info, trace, warn};
use wasmtime::{
    Config, Engine, Store, StoreLimits, StoreLimitsBuilder, Trap,
    component::{Component, Linker},
};

use super::wit::{
    Bindings, LogHost, TypesHost, WitLevel, bundled::BundledBindings,
    containers::ContainerBindings, machines::MachineBindings, recipe::RecipeBindings,
    vm::VmBindings,
};

/// Instructions one call may execute before it traps.
///
/// Generous enough that no honest plugin will reach it - the reference plugins in
/// `plugins/` classify a command in well under ten thousand - and small enough that a
/// plugin spinning in a loop is stopped in a fraction of a second rather than hanging
/// the build for ever.
const FUEL: u64 = 200_000_000;

/// Largest linear memory one plugin instance may grow to.
///
/// A source file reaching the guest is already capped at
/// [`crate::perms::source::MAX_FILE_BYTES`], so this is roomy for the only input that
/// can be large at all.
const MEMORY_BYTES: usize = 64 << 20;

/// Instructions one call into a **bundled** plugin may execute.
///
/// Bundled plugins are pm's own code, shipped inside the binary, and the source scanners
/// among them parse a whole file with a real grammar - up to
/// [`crate::perms::source::MAX_FILE_BYTES`] of C++ - where a reference plugin matches a
/// token stream. The budget is still there so that a bug in one is a logged trap rather
/// than a hang, but it is sized for a parser, not for a lookup table.
const BUNDLED_FUEL: u64 = 50_000_000_000;

/// Largest linear memory one bundled plugin instance may grow to.
///
/// A bundled instance lives for the whole scan on its thread (see [`Live`]) and keeps
/// its compiled queries, so it needs room for those beside one file's syntax tree.
const BUNDLED_MEMORY_BYTES: usize = 1 << 30;

/// Largest table one plugin instance may grow to, in elements.
const TABLE_ELEMENTS: usize = 10_000;

/// How many core WebAssembly instances one component may be built out of.
const MAX_CORE_INSTANCES: usize = 32;

/// How many linear memories one component may hold.
const MAX_MEMORIES: usize = 4;

/// How many tables one component may hold.
const MAX_TABLES: usize = 8;

/// Native stack one call may use, in bytes.
const STACK_BYTES: usize = 512 << 10;

/// Longest log line a plugin may write before it is truncated.
///
/// A plugin logs to help whoever is debugging it; it does not get to bury a build's
/// output. The cut is marked so a truncated line cannot be mistaken for a whole one.
const MAX_LOG_BYTES: usize = 4 << 10;

/// What suffix a truncated log line carries.
const TRUNCATION_MARK: &str = " ... [truncated]";

/// The engine and linker every plugin of one [`super::Registry`] shares.
///
/// Compiling a component is the expensive part and it happens once, at load. Calls are
/// cheap afterwards, and safe to make from several threads at once: [`Component`] and
/// [`Linker`] are both `Sync`, and the mutable per-call state lives in the [`Store`]
/// that [`Runtime::enter`] creates and drops.
pub(super) struct Runtime {
    engine: Engine,
    linker: Linker<State>,
}

impl Runtime {
    /// Build the engine and define the one import a plugin gets.
    ///
    /// # Errors
    ///
    /// Fails if the configuration is not one this build of wasmtime supports, or if the
    /// `log` import cannot be defined - both of which are bugs in this module rather
    /// than anything about a plugin.
    pub(super) fn new() -> Result<Self> {
        let mut config = Config::new();
        config
            .wasm_component_model(true)
            // The meter that makes a runaway plugin a trap rather than a hang.
            .consume_fuel(true)
            // Relaxed SIMD is the one proposal whose results are allowed to differ
            // between hosts. A plugin's answer feeds a policy digest, so it has to be
            // the same answer everywhere.
            .relaxed_simd_deterministic(true)
            .max_wasm_stack(STACK_BYTES);
        // The threads proposal is not compiled into this build of wasmtime at all - it
        // is behind a cargo feature pm does not enable - so there is nothing to turn
        // off here. Do not enable it: shared memory and atomics would give a plugin a
        // second thread to do work in that the fuel meter on this one does not see.

        let engine = Engine::new(&config).map_err(|error| {
            miette!("cannot start the WebAssembly engine plugins run in: {error:?}")
        })?;

        let mut linker: Linker<State> = Linker::new(&engine);
        // The ONLY `add_to_linker` call in this crate. Adding a second one - `wasi`,
        // most temptingly - hands every installed plugin whatever it defines, in pm's
        // own process, with pm's own privileges.
        Bindings::add_to_linker::<State, wasmtime::component::HasSelf<State>>(
            &mut linker,
            |state| state,
        )
        .map_err(|error| miette!("cannot define the plugin host interface: {error:?}"))?;

        Ok(Self { engine, linker })
    }

    /// Compile `bytes` into a component, ready to be instantiated.
    ///
    /// # Errors
    ///
    /// Fails if `bytes` is not a valid WebAssembly component - which includes the case
    /// of a plain core module, since a plugin has to be a component.
    pub(super) fn compile(&self, bytes: &[u8]) -> Result<Component> {
        Component::new(&self.engine, bytes).map_err(|error| {
            miette!(
                help = "A plugin must be a WebAssembly *component* built against \
                        `wit/plugin.wit`. A core module built with \
                        `--target wasm32-unknown-unknown` still has to go through \
                        `wasm-tools component new`; see `plugins/README.md`.",
                "not a usable WebAssembly component: {error:?}"
            )
        })
    }

    /// Instantiate `component` in a store of its own and hand it to `call`.
    ///
    /// The store, its instance and its memory are created here and dropped before this
    /// returns, so a plugin's answer cannot depend on anything but its argument.
    ///
    /// # Errors
    ///
    /// Fails if the component does not instantiate - which is what happens to one whose
    /// imports are not exactly the world's - or if `call` traps, runs out of
    /// [`FUEL`] or exceeds a store limit. Every one of those is a fault of the plugin,
    /// and the callers in [`super`] treat it as "this plugin had no answer" rather than
    /// letting it fail a build.
    pub(super) fn enter<T>(
        &self,
        plugin: &str,
        component: &Component,
        call: impl FnOnce(&Bindings, &mut Store<State>) -> wasmtime::Result<T>,
    ) -> Result<T> {
        self.enter_as(
            plugin,
            component,
            |store, component, linker| Bindings::instantiate(store, component, linker),
            call,
        )
    }

    /// [`Runtime::enter`] for a plugin built against the `recipe-plugin` world, to call
    /// the exports that world adds.
    ///
    /// # Errors
    ///
    /// As [`Runtime::enter`].
    pub(super) fn enter_recipe<T>(
        &self,
        plugin: &str,
        component: &Component,
        call: impl FnOnce(&RecipeBindings, &mut Store<State>) -> wasmtime::Result<T>,
    ) -> Result<T> {
        self.enter_as(
            plugin,
            component,
            |store, component, linker| RecipeBindings::instantiate(store, component, linker),
            call,
        )
    }

    /// Whether `component` exports what the `recipe-plugin` world adds, so
    /// [`Runtime::enter_recipe`] can instantiate it.
    pub(super) fn has_recipe_functions(component: &Component) -> bool {
        ["recipe-functions", "call-recipe-function"]
            .into_iter()
            .all(|export| component.get_export_index(None, export).is_some())
    }

    /// [`Runtime::enter`] for a plugin built against the `vm-plugin` world, to call
    /// the exports that world adds.
    ///
    /// # Errors
    ///
    /// As [`Runtime::enter`].
    pub(super) fn enter_vm<T>(
        &self,
        plugin: &str,
        component: &Component,
        call: impl FnOnce(&VmBindings, &mut Store<State>) -> wasmtime::Result<T>,
    ) -> Result<T> {
        self.enter_as(
            plugin,
            component,
            |store, component, linker| VmBindings::instantiate(store, component, linker),
            call,
        )
    }

    /// Whether `component` exports what the `vm-plugin` world adds, so
    /// [`Runtime::enter_vm`] can instantiate it.
    pub(super) fn has_launchers(component: &Component) -> bool {
        ["launchers", "launch-machine"]
            .into_iter()
            .all(|export| component.get_export_index(None, export).is_some())
    }

    /// [`Runtime::enter`] for a plugin built against the `machine-plugin` world, to
    /// call the export that world adds.
    ///
    /// # Errors
    ///
    /// As [`Runtime::enter`].
    pub(super) fn enter_machine<T>(
        &self,
        plugin: &str,
        component: &Component,
        call: impl FnOnce(&MachineBindings, &mut Store<State>) -> wasmtime::Result<T>,
    ) -> Result<T> {
        self.enter_as(
            plugin,
            component,
            |store, component, linker| MachineBindings::instantiate(store, component, linker),
            call,
        )
    }

    /// Whether `component` exports what the `machine-plugin` world adds, so
    /// [`Runtime::enter_machine`] can instantiate it.
    pub(super) fn has_machine_plan(component: &Component) -> bool {
        Self::has_launchers(component) && component.get_export_index(None, "machine-plan").is_some()
    }

    /// [`Runtime::enter`] for a plugin built against the `container-plugin` world, to
    /// call the export that world adds.
    ///
    /// # Errors
    ///
    /// As [`Runtime::enter`].
    pub(super) fn enter_container<T>(
        &self,
        plugin: &str,
        component: &Component,
        call: impl FnOnce(&ContainerBindings, &mut Store<State>) -> wasmtime::Result<T>,
    ) -> Result<T> {
        self.enter_as(
            plugin,
            component,
            |store, component, linker| ContainerBindings::instantiate(store, component, linker),
            call,
        )
    }

    /// Whether `component` exports what the `container-plugin` world adds, so
    /// [`Runtime::enter_container`] can instantiate it.
    pub(super) fn has_container_plan(component: &Component) -> bool {
        Self::has_launchers(component)
            && component.get_export_index(None, "container-plan").is_some()
    }

    fn enter_as<B, T>(
        &self,
        plugin: &str,
        component: &Component,
        instantiate: impl FnOnce(&mut Store<State>, &Component, &Linker<State>) -> wasmtime::Result<B>,
        call: impl FnOnce(&B, &mut Store<State>) -> wasmtime::Result<T>,
    ) -> Result<T> {
        let mut store = Store::new(&self.engine, State::new(plugin));
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(FUEL)
            .map_err(|error| miette!("cannot meter the plugin {plugin}: {error:?}"))?;

        let bindings = instantiate(&mut store, component, &self.linker)
            .map_err(|error| describe(plugin, "instantiate", FUEL, &mut store, &error))?;

        let outcome = call(&bindings, &mut store);
        let spent = FUEL.saturating_sub(store.get_fuel().unwrap_or(0));
        trace!(plugin, fuel = spent, "plugin call finished");
        outcome.map_err(|error| describe(plugin, "call", FUEL, &mut store, &error))
    }

    /// Instantiate a **bundled** plugin, for [`Live::call`] to call into repeatedly.
    ///
    /// The one place pm keeps an instance across calls, and only for its own plugins:
    /// the tree-sitter scanners compile their queries once per instance, and compiling a
    /// query costs far more than running one. The isolation a fresh instance buys - one
    /// file cannot influence what another is found to need - is a defence against a
    /// plugin pm did not write; a bundled plugin is part of the pm binary that was
    /// signed and installed, the same code these tables were before they were
    /// components.
    ///
    /// # Errors
    ///
    /// Fails if the component does not instantiate, which for a bundled plugin is a bug
    /// in pm.
    pub(super) fn instantiate_bundled(&self, plugin: &str, component: &Component) -> Result<Live> {
        let mut store = Store::new(&self.engine, State::bundled(plugin));
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(BUNDLED_FUEL)
            .map_err(|error| miette!("cannot meter the plugin {plugin}: {error:?}"))?;
        let bindings = BundledBindings::instantiate(&mut store, component, &self.linker)
            .map_err(|error| describe(plugin, "instantiate", BUNDLED_FUEL, &mut store, &error))?;
        Ok(Live { store, bindings })
    }
}

/// A bundled plugin's instance, kept for the calls one thread makes into it.
///
/// See [`Runtime::instantiate_bundled`] for why this exists at all. Each call is still
/// metered on its own - the fuel is topped up to [`BUNDLED_FUEL`] before it - and an
/// instance that trapped is the caller's to throw away, since a trap can leave the
/// guest's memory half-updated.
pub(super) struct Live {
    store: Store<State>,
    bindings: BundledBindings,
}

impl Live {
    /// Call into the instance.
    ///
    /// # Errors
    ///
    /// As [`Runtime::enter`]: a trap, running out of fuel or exceeding a store limit.
    /// The instance must not be used again after an error.
    pub(super) fn call<T>(
        &mut self,
        plugin: &str,
        call: impl FnOnce(&BundledBindings, &mut Store<State>) -> wasmtime::Result<T>,
    ) -> Result<T> {
        self.store
            .set_fuel(BUNDLED_FUEL)
            .map_err(|error| miette!("cannot meter the plugin {plugin}: {error:?}"))?;
        let outcome = call(&self.bindings, &mut self.store);
        let spent = BUNDLED_FUEL.saturating_sub(self.store.get_fuel().unwrap_or(0));
        trace!(plugin, fuel = spent, "bundled plugin call finished");
        outcome.map_err(|error| describe(plugin, "call", BUNDLED_FUEL, &mut self.store, &error))
    }
}

/// Everything one plugin call may touch, which is the limits and its own name.
///
/// The name is here only so [`LogHost::log`] can tag the plugin's output; nothing the
/// guest can call reads it back.
pub(super) struct State {
    plugin: String,
    limits: StoreLimits,
}

impl State {
    /// A fresh state for one call by `plugin`.
    fn new(plugin: &str) -> Self {
        Self::with_memory(plugin, MEMORY_BYTES)
    }

    /// The state a bundled plugin's long-lived instance runs in.
    fn bundled(plugin: &str) -> Self {
        Self::with_memory(plugin, BUNDLED_MEMORY_BYTES)
    }

    fn with_memory(plugin: &str, memory: usize) -> Self {
        Self {
            plugin: plugin.to_owned(),
            limits: StoreLimitsBuilder::new()
                .memory_size(memory)
                .table_elements(TABLE_ELEMENTS)
                // These count the *core* instances, memories and tables inside one
                // component, not plugins: the adapters `wit-bindgen` emits mean even a
                // trivial plugin is several core modules linked together. The numbers
                // are a backstop against a component whose instance graph is absurd,
                // not a budget anybody should be tuning - what actually bounds a
                // plugin is the fuel above and [`MEMORY_BYTES`].
                .instances(MAX_CORE_INSTANCES)
                .memories(MAX_MEMORIES)
                .tables(MAX_TABLES)
                .build(),
        }
    }
}

// The `types` interface declares no functions, so the trait it generates is empty. It
// still has to be implemented, because the world `use`s the interface.
impl TypesHost for State {}

impl LogHost for State {
    /// Write a plugin's line into pm's log, tagged with the plugin's name.
    ///
    /// Returns nothing, deliberately: see the module documentation for why a one-way
    /// import is the only kind a plugin can be given without giving up determinism.
    fn log(&mut self, level: WitLevel, message: String) {
        let message = truncate(message);
        let plugin = self.plugin.as_str();
        match level {
            WitLevel::Error => error!(plugin, "{message}"),
            WitLevel::Warn => warn!(plugin, "{message}"),
            WitLevel::Info => info!(plugin, "{message}"),
            WitLevel::Debug => debug!(plugin, "{message}"),
            WitLevel::Trace => trace!(plugin, "{message}"),
        }
    }
}

/// Cut `message` to [`MAX_LOG_BYTES`], marking the cut.
///
/// Truncation is on a character boundary, because the message is already a `String` and
/// slicing it anywhere else would panic.
fn truncate(mut message: String) -> String {
    if message.len() <= MAX_LOG_BYTES {
        return message;
    }
    let mut cut = MAX_LOG_BYTES;
    while cut > 0 && !message.is_char_boundary(cut) {
        cut -= 1;
    }
    message.truncate(cut);
    message.push_str(TRUNCATION_MARK);
    message
}

/// Turn a wasmtime failure into a diagnostic that says which plugin, doing what, and -
/// where wasmtime can tell us - why.
///
/// Running out of fuel and blowing the stack are called out by name because they are
/// the two a plugin author will actually hit, and the raw trap text ("all fuel
/// consumed by WebAssembly") does not say which of pm's limits was reached.
fn describe(
    plugin: &str,
    what: &str,
    fuel: u64,
    store: &mut Store<State>,
    error: &wasmtime::Error,
) -> miette::Report {
    match error.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => miette!(
            help = "The plugin ran past the per-call instruction budget. That is a \
                    runaway loop far more often than it is a plugin that needs more \
                    room.",
            "the plugin {plugin} used all {fuel} units of fuel during {what}"
        ),
        Some(Trap::StackOverflow) => {
            miette!("the plugin {plugin} overflowed its {STACK_BYTES}-byte stack during {what}")
        }
        _ => {
            let left = store.get_fuel().unwrap_or(0);
            debug!(plugin, fuel_left = left, "plugin failed");
            miette!("the plugin {plugin} failed to {what}: {error:?}")
        }
    }
}

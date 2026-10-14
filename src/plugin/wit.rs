//! The bindings generated from `wit/plugin.wit`.
//!
//! The generated tree is rooted at `pm::plugin::*` - the WIT package name, which is
//! also the name of this crate - so it lives in a module of its own rather than at the
//! crate root, where `pm::plugin::types` (the guest's view) and `crate::plugin` (the
//! host's) would be two unrelated things spelled almost the same.
//!
//! Nothing here is written by hand and nothing here is public: [`super::convert`] turns
//! every generated value into the pm type it mirrors before it reaches the rest of the
//! crate, so the generated names stop at this module's boundary.

// The generated code is not ours to lint.
#![allow(clippy::all, clippy::pedantic, missing_docs, unreachable_pub)]

wasmtime::component::bindgen!({
    path: "wit",
    world: "plugin",
});

pub(super) use self::{
    Plugin as Bindings,
    pm::plugin::{
        host::{Host as LogHost, Level as WitLevel},
        types::{
            Capability as WitCapability, DiskFormat as WitDiskFormat, Firmware as WitFirmware,
            Grant as WitGrant, Hook as WitHook, Host as TypesHost, Launch as WitLaunch,
            Machine as WitMachine, MachineLabel as WitMachineLabel,
            MachineRequest as WitMachineRequest, MachineSpec as WitMachineSpec,
            MachineStep as WitMachineStep, MachineTemplate as WitMachineTemplate,
            Manifest as WitManifest, Permission as WitPermission,
            RecipeFunction as WitRecipeFunction, RecipeValue as WitRecipeValue,
            SourceFile as WitSourceFile, Symbol as WitSymbol, Verdict as WitVerdict,
        },
    },
};

/// The bindings for the `bundled` world: everything above, plus the `fingerprints`
/// export pm's own plugins carry.
///
/// The shared interfaces are mapped onto the modules generated above, so a
/// `Manifest`, a `Verdict` or the `log` host is one type whichever world produced it,
/// and one [`wasmtime::component::Linker`] serves both.
pub(super) mod bundled {
    #![allow(clippy::all, clippy::pedantic, missing_docs, unreachable_pub)]

    wasmtime::component::bindgen!({
        path: "wit",
        world: "bundled",
        with: {
            "pm:plugin/types": super::pm::plugin::types,
            "pm:plugin/host": super::pm::plugin::host,
        },
    });

    pub(in crate::plugin) use self::Bundled as BundledBindings;
}

/// The bindings for the `recipe-plugin` world: everything a plugin exports, plus the
/// functions it adds to Rhai recipes.
///
/// Mapped onto the same shared interfaces as [`bundled`], so one linker serves all
/// three worlds.
pub(super) mod recipe {
    #![allow(clippy::all, clippy::pedantic, missing_docs, unreachable_pub)]

    wasmtime::component::bindgen!({
        path: "wit",
        world: "recipe-plugin",
        with: {
            "pm:plugin/types": super::pm::plugin::types,
            "pm:plugin/host": super::pm::plugin::host,
        },
    });

    pub(in crate::plugin) use self::RecipePlugin as RecipeBindings;
}

/// The bindings for the `vm-plugin` world: everything a plugin exports, plus the
/// programs it may have pm run and the call that starts a virtual machine.
///
/// Mapped onto the same shared interfaces as [`bundled`], so one linker serves every
/// world.
pub(super) mod vm {
    #![allow(clippy::all, clippy::pedantic, missing_docs, unreachable_pub)]

    wasmtime::component::bindgen!({
        path: "wit",
        world: "vm-plugin",
        with: {
            "pm:plugin/types": super::pm::plugin::types,
            "pm:plugin/host": super::pm::plugin::host,
        },
    });

    pub(in crate::plugin) use self::VmPlugin as VmBindings;
}

/// The bindings for the `machine-plugin` world: everything a `vm-plugin` exports, plus
/// the call that turns a request about the host's machines into steps.
///
/// Mapped onto the same shared interfaces as [`bundled`], so one linker serves every
/// world.
pub(super) mod machines {
    #![allow(clippy::all, clippy::pedantic, missing_docs, unreachable_pub)]

    wasmtime::component::bindgen!({
        path: "wit",
        world: "machine-plugin",
        with: {
            "pm:plugin/types": super::pm::plugin::types,
            "pm:plugin/host": super::pm::plugin::host,
        },
    });

    pub(in crate::plugin) use self::MachinePlugin as MachineBindings;
}

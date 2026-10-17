#!/bin/sh
# Build every plugin in this workspace and encode it as a WebAssembly component.
#
# Two steps, because `cargo build --target wasm32-unknown-unknown` stops at a core
# module: the canonical-ABI shims `wit-bindgen` generated are in it, but nothing has
# wrapped them in a component yet. `encoder/` does that - `wasm-tools component new`
# does the same job if you have it installed.
#
#   ./build.sh            build everything into dist/
#   ./build.sh zig        build one crate into dist/
#
# pm's own bundled plugins (bundled/) are not built here: pm's build.rs builds them on
# every `cargo build` of pm.
#
# Requires a Rust toolchain with the wasm32-unknown-unknown target, and the
# wasm32-wasip2 target when building every plugin:
#
#   rustup target add wasm32-unknown-unknown wasm32-wasip2
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

target=wasm32-unknown-unknown
out="$here/dist"
crates=${*:-"libvirt quickemu systemd sysext sysupdate zig greedy runaway nameless scanner launcher"}

mkdir -p "$out"
cargo build --release --target "$target" $(for c in $crates; do echo "-p $c"; done)
cargo build --release -p encoder

for crate in $crates; do
    module="$here/target/$target/release/$(echo "$crate" | tr - _).wasm"
    "$here/target/release/encoder" "$module" "$out/$crate.wasm"
done

# The `wasi` fixture is the exception: it exists to import things pm does not lend a
# plugin, so it is built for wasm32-wasip2, which links a WASI libc. rustc emits a
# component for that target itself, so there is nothing to encode.
#
#   rustup target add wasm32-wasip2
if [ $# -eq 0 ]; then
    cargo build --release --target wasm32-wasip2 -p wasi
    cp "$here/target/wasm32-wasip2/release/wasi.wasm" "$out/wasi.wasm"
fi

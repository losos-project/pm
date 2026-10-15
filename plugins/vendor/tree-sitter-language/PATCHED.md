# tree-sitter-language 0.1.9, patched for pm's bundled plugins

An unmodified copy of the published crate (MIT, see `LICENSE`) except for two things,
both needed to build tree-sitter grammars for `wasm32-unknown-unknown` with tree-sitter
0.27:

* `build.rs` advertises `wasm/empty/` as `wasm-src`. The published crate points there at
  files that `#error` on purpose, because tree-sitter up to 0.26 compiled them as its
  libc. tree-sitter 0.27 brings its own libc, but the grammar crates pm uses still compile
  whatever `wasm-src` names, so the files there are now empty.
* `wasm/include/` gains what the grammars' external scanners use and the published
  headers lack: `static_assert` in `assert.h`, the ASCII `ctype.h` classifiers as inline
  functions, and `wchar_t` reaching `wctype.h`.

`plugins/Cargo.toml` selects this copy with `[patch.crates-io]`, and `plugins/build.sh`
adds `wasm/include/` to the C include path for the grammars that do not add it
themselves. Drop both once the grammar crates stop compiling `wasm-src`.

//! A PE/COFF linker for MinGW cross-compilation.
//!
//! This crate implements mold's Windows target: it links COFF object files
//! produced by `x86_64-w64-mingw32-gcc` into PE32+ executables and DLLs.
//! The design follows the C++ prototype that lived in `src/pe-coff/`:
//!
//! - `pe` holds the on-disk format constants and parsing helpers.
//! - `context` holds the linker's in-memory data structures.
//! - `filetype` classifies input files.
//! - `input_files` parses COFF objects, archives and import libraries.
//! - `cmdline` parses GNU-ld-compatible MinGW options.
//! - `passes` resolves symbols, merges sections and builds tables.
//! - `pseudo_reloc` emits MinGW runtime pseudo-relocs for imported data.
//! - `relocations` applies COFF relocations.
//! - `output` computes the image layout and writes headers.
//! - `writer` assembles the final file.
//! - `auto_export` implements `--export-all-symbols` filtering.
//! - `driver` is the entry point used by the `mold` executable.

pub mod auto_export;
pub mod cmdline;
pub mod context;
pub mod driver;
pub mod filetype;
pub mod input_files;
pub mod output;
pub mod passes;
pub mod pe;
pub mod pseudo_reloc;
pub mod relocations;
pub mod writer;

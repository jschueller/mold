//! `--export-all-symbols` filtering, following lld's AutoExporter.
//!
//! Ported from `src/pe-coff/auto-export.cc`.

use crate::context::Context;
use crate::pe::IMAGE_SYM_CLASS_STATIC;

const EXCLUDED_LIBS: &[&str] = &[
    "libgcc",
    "libstdc++",
    "libmingw32",
    "libmingwex",
    "libsupc++",
    "libobjc",
    "libgcj",
    "libclang_rt",
    "libcygwin",
    "libc++",
    "libunwind",
    "libmsvcrt",
    "libucrt",
    "libwinpthread",
    "libgcc_s",
    "libgcc_eh",
    "libgfortran",
    "libquadmath",
    "libatomic",
    "libgomp",
    "libssp",
];

const EXCLUDED_OBJECTS: &[&str] = &[
    "crt0.o",
    "crt1.o",
    "crt1u.o",
    "dllcrt1.o",
    "dllcrt2.o",
    "gcrt0.o",
    "gcrt1.o",
    "crtbegin.o",
    "crtend.o",
    "crtbeginT.o",
    "crtendT.o",
    "crtbeginS.o",
    "crtendS.o",
    "crtbeginD.o",
    "crtendD.o",
    "dllmain.o",
];

const EXCLUDED_PREFIXES: &[&[u8]] = &[
    b"__imp_",
    b"__IMPORT_DESCRIPTOR_",
    b"__nm_",
    b"__rtti_",
    b"__profc_",
    b"__profd_",
    b"__pyx_",
    b"___pyx_",
    b"_imp_",
    b".",
];

fn file_name_of(ctx: &Context, id: usize) -> Vec<u8> {
    let sym = &ctx.symbols[id];
    let Some(file) = sym.file else {
        return Vec::new();
    };
    let name = &ctx.files[file].name;
    let bytes = name.as_os_str().as_encoded_bytes();
    match bytes.iter().rposition(|&c| c == b'/' || c == b'\\') {
        Some(i) => bytes[i + 1..].to_vec(),
        None => bytes.to_vec(),
    }
}

fn is_excluded_library(ctx: &Context, id: usize) -> bool {
    let filename = file_name_of(ctx, id);
    if filename.is_empty() {
        return false;
    }
    let lower = String::from_utf8_lossy(&filename).to_ascii_lowercase();
    for lib in EXCLUDED_LIBS {
        if lower.starts_with(lib) {
            let rest = &lower[lib.len()..];
            if rest.is_empty()
                || rest.starts_with('.')
                || rest.starts_with('-')
                || rest.starts_with(|c: char| c.is_ascii_digit())
            {
                return true;
            }
        }
    }
    for obj in EXCLUDED_OBJECTS {
        if lower == *obj {
            return true;
        }
    }
    false
}

pub fn should_export_symbol(ctx: &Context, id: usize) -> bool {
    let sym = &ctx.symbols[id];
    if !sym.is_defined {
        return false;
    }
    if is_excluded_library(ctx, id) {
        return false;
    }
    for prefix in EXCLUDED_PREFIXES {
        if sym.name.starts_with(prefix) {
            return false;
        }
    }
    // stdcall-decorated symbols (`foo@12`) are not auto-exported.
    if sym.name.contains(&b'@') {
        return false;
    }
    if sym.storage_class == IMAGE_SYM_CLASS_STATIC {
        return false;
    }
    if sym.is_comdat || sym.is_weak {
        return false;
    }
    let imp_name = [b"__imp_".as_slice(), sym.name.as_slice()].concat();
    if ctx.find(&imp_name).is_some() {
        return false;
    }
    true
}

pub fn collect_auto_exports(ctx: &Context) -> Vec<(Vec<u8>, usize)> {
    let mut out = Vec::new();
    for (id, sym) in ctx.symbols.iter().enumerate() {
        if sym.name.is_empty() {
            continue;
        }
        if should_export_symbol(ctx, id) {
            out.push((sym.name.clone(), id));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

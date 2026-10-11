//! Driver: from command line to output file.
//!
//! The flow mirrors the C++ `pecoff_main`: parse args, read direct objects
//! and archives, resolve `-l` libraries, collect symbols, extract archive
//! members for undefined symbols, re-resolve imports, run passes, write.

use std::borrow::Cow;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use mold_common::mapped_file::{MappedFile, must_open_file, open_file};
use mold_common::{error, fatal};
use rayon::prelude::*;

use crate::cmdline::parse_args;
use crate::context::{Archive, CoffObject, Context, ImportObject};
use crate::filetype::{FileType, get_file_type, get_pe_target, pe_machine_of};
use crate::input_files::{self, parse_archive};

pub type Cmdline = Vec<Cow<'static, OsStr>>;

pub fn main(argv: Vec<OsString>) {
    let cmdline: Cmdline = mold_common::response_file::expand_response_files(argv, false);
    link(cmdline);
    std::process::exit(0);
}

fn find_library(ctx: &Context, name: &OsStr) -> Option<PathBuf> {
    let name = name.as_encoded_bytes();
    let mut candidates = Vec::new();
    let stem = String::from_utf8_lossy(name).into_owned();
    // Prefer the target's sysroot; the other arch's libraries would be
    // rejected as conflicting architectures if picked up.
    let arm64_first = ctx.target_machine == crate::pe::COFF_MACHINE_ARM64;
    let (first_fallback, second_fallback) = if arm64_first {
        ("/usr/aarch64-w64-mingw32/lib", "/usr/x86_64-w64-mingw32/lib")
    } else {
        ("/usr/x86_64-w64-mingw32/lib", "/usr/aarch64-w64-mingw32/lib")
    };
    let fallbacks = [PathBuf::from(first_fallback), PathBuf::from(second_fallback)];
    for dir in ctx.args.library_paths.iter().chain(fallbacks.iter()) {
        for cand in [
            dir.join(format!("lib{stem}.dll.a")),
            dir.join(format!("lib{stem}.a")),
            dir.join(format!("{stem}.dll.a")),
            dir.join(format!("{stem}.a")),
            dir.join(format!("lib{stem}.lib")),
        ] {
            candidates.push(cand);
        }
    }
    candidates.into_iter().find(|p| {
        let Some(mf) = open_file(&ctx.args.chroot, p) else {
            return false;
        };
        // Never pick a library for the wrong architecture (e.g. an x86-64
        // import library when linking ARM64 with an undetermined target).
        if ctx.target_machine == 0 {
            return true;
        }
        match get_file_type(mf) {
            FileType::CoffObj => pe_machine_of(mf.data()) == ctx.target_machine,
            FileType::CoffArchive => {
                archive_machine(mf.data()).map_or(true, |m| m == ctx.target_machine)
            }
            _ => false,
        }
    })
}

/// Machine of an archive's first object-like member, if determinable.
/// Thin archives and member-less archives yield `None` (not rejected).
fn archive_machine(data: &[u8]) -> Option<u16> {
    if data.len() < 8 || &data[..8] != b"!<arch>\n" {
        return None;
    }
    let mut off = 8usize;
    while off + 60 <= data.len() {
        if &data[off..off + 8] == b"!<arch>\n" || &data[off + 58..off + 60] != b"`\n" {
            break;
        }
        let mut end = 16usize;
        while end > 0 && data[off + end - 1] == b' ' {
            end -= 1;
        }
        let name = &data[off..off + end];
        let size: usize =
            std::str::from_utf8(&data[off + 48..off + 58]).ok()?.trim().parse().ok()?;
        off += 60;
        if off + size > data.len() {
            return None;
        }
        let special = name == b"/" || name == b"//" || name == b"__.SYMDEF" || name == b"/SYM64/";
        if !special && size >= 2 {
            if size >= 8
                && data[off] == 0
                && data[off + 1] == 0
                && data[off + 2] == 0xFF
                && data[off + 3] == 0xFF
            {
                return Some(u16::from_le_bytes([data[off + 6], data[off + 7]]));
            }
            return Some(u16::from_le_bytes([data[off], data[off + 1]]));
        }
        off += (size + 1) & !1;
    }
    None
}

/// Result of reading one input file on a worker thread. Merged into the
/// context in command-line order afterwards, keeping every subsequent
/// pass deterministic.
enum ReadOutcome {
    Obj(CoffObject, u16, &'static MappedFile),
    Archive(Archive),
    PeFile(PathBuf),
    Empty,
}

fn read_input_file(mf: &'static MappedFile) -> ReadOutcome {
    match get_file_type(mf) {
        FileType::CoffObj => {
            let data = mf.data();
            // SAFETY: mapped input lives for the whole link.
            let bytes: &'static [u8] =
                unsafe { std::slice::from_raw_parts(data.as_ptr(), data.len()) };
            let name = mf.name.clone();
            let (obj, machine) = input_files::parse_coff_bytes(&name, bytes);
            ReadOutcome::Obj(obj, machine, mf)
        }
        FileType::CoffArchive => ReadOutcome::Archive(parse_archive(mf)),
        FileType::PeFile => ReadOutcome::PeFile(mf.name.clone()),
        FileType::Empty => ReadOutcome::Empty,
        FileType::Unknown => {
            fatal!("{}: unknown file type", mf.name.display());
        }
    }
}

/// Pushes a parsed object, enforcing the single-architecture rule.
/// Shared by direct inputs and archive members.
fn commit_object(ctx: &mut Context, name: &Path, obj: CoffObject, machine: u16) -> usize {
    if ctx.target_machine == 0 {
        ctx.target_machine = machine;
    } else if machine != ctx.target_machine {
        fatal!("{}: conflicting architectures in one link", name.display());
    }
    let id = ctx.files.len();
    ctx.files.push(obj);
    id
}

fn commit_read(ctx: &mut Context, outcome: ReadOutcome, whole: bool) {
    match outcome {
        ReadOutcome::Obj(obj, machine, mf) => {
            let data = mf.data();
            // SAFETY: mapped input lives for the whole link.
            let bytes: &'static [u8] =
                unsafe { std::slice::from_raw_parts(data.as_ptr(), data.len()) };
            let id = commit_object(ctx, &mf.name, obj, machine);
            // Import-library members passed directly still need import
            // registration. Only their `.idata` sections die (the import
            // table is synthetic); the `.text` thunk stays live.
            if input_files::is_import_member(&ctx.files[id]) {
                let imports = input_files::parse_import_entries(&ctx.files[id], bytes);
                if !imports.is_empty() {
                    for sec in ctx.files[id].sections.iter_mut() {
                        if sec.name.starts_with(b".idata") {
                            sec.is_alive = false;
                        }
                    }
                    ctx.import_objects.push(ImportObject { name: mf.name.clone(), imports });
                }
            }
        }
        ReadOutcome::Archive(mut archive) => {
            if whole {
                archive.extract_all = true;
            }
            ctx.archives.push(archive);
        }
        ReadOutcome::PeFile(name) => {
            input_files::warn_pe_file(&name);
        }
        ReadOutcome::Empty => {}
    }
}

/// Below this batch size, parse serially: a rayon region costs more
/// than it saves, especially under load.
const SERIAL_BATCH: usize = 32;

/// Parses reserved archive members in parallel and merges them in order.
/// Members are reserved (marked `extracted`) serially beforehand so that
/// picks observe the same state as a serial extractor; the ordered merge
/// re-validates each hit against live state, reproducing serial decisions
/// exactly (a name defined by an earlier commit in the same batch is
/// skipped, and its reservation is released).
fn extract_reserved(ctx: &mut Context, work: &[(Vec<u8>, usize, usize)]) -> bool {
    if work.len() < SERIAL_BATCH {
        // Small batch: identical work to the old serial extractor.
        let mut extracted_any = false;
        for (name, ar_idx, m_idx) in work {
            let defined = ctx.symbol_map.get(name).is_some_and(|&id| !ctx.symbols[id].is_undefined);
            if defined {
                ctx.archives[*ar_idx].members[*m_idx].extracted = false;
                continue;
            }
            let parsed = (|| {
                let ar = &ctx.archives[*ar_idx];
                let (bytes, member_name) = input_files::member_bytes(ar, *m_idx)?;
                let (obj, machine) = input_files::parse_coff_bytes(&member_name, bytes);
                Some((obj, machine, member_name))
            })();
            let Some((obj, machine, member_name)) = parsed else {
                continue;
            };
            let id = commit_object(ctx, &member_name, obj, machine);
            register_extracted_object(ctx, id);
            extracted_any = true;
        }
        return extracted_any;
    }
    struct Parsed {
        obj: CoffObject,
        machine: u16,
        name: PathBuf,
    }
    let ctx_ref: &Context = ctx;
    let parsed: Vec<Option<Parsed>> = work
        .into_par_iter()
        .map(|(_, ar_idx, m_idx)| {
            let ar = &ctx_ref.archives[*ar_idx];
            let (bytes, member_name) = input_files::member_bytes(ar, *m_idx)?;
            let (obj, machine) = input_files::parse_coff_bytes(&member_name, bytes);
            Some(Parsed { obj, machine, name: member_name })
        })
        .collect();
    let mut extracted_any = false;
    for ((name, ar_idx, m_idx), parsed) in work.iter().zip(parsed) {
        // Re-validate: a name defined by an earlier commit in this batch
        // needs nothing; release its reservation untouched.
        let defined = ctx.symbol_map.get(name).is_some_and(|&id| !ctx.symbols[id].is_undefined);
        if defined {
            ctx.archives[*ar_idx].members[*m_idx].extracted = false;
            continue;
        }
        let Some(parsed) = parsed else {
            // Non-COFF member stays marked to avoid retrying, as before.
            continue;
        };
        let id = commit_object(ctx, &parsed.name, parsed.obj, parsed.machine);
        register_extracted_object(ctx, id);
        extracted_any = true;
    }
    extracted_any
}

fn resolve_from_archives(
    ctx: &mut Context,
    providers: &hashbrown::HashMap<Vec<u8>, Vec<(usize, usize)>>,
) {
    // First unextracted candidate wins, exactly as the old per-archive
    // scan did.
    fn pick(
        ctx: &Context,
        providers: &hashbrown::HashMap<Vec<u8>, Vec<(usize, usize)>>,
        name: &[u8],
    ) -> Option<(usize, usize)> {
        providers.get(name).and_then(|cands| {
            cands.iter().find(|&&(ar_idx, m)| !ctx.archives[ar_idx].members[m].extracted).copied()
        })
    }
    // Only symbols added since the previous iteration can be newly
    // undefined: the provider maps are static and extraction only removes
    // candidates, so an old miss stays a miss.
    let mut scanned = 0usize;
    for _ in 0..100 {
        // Collect undefined symbol names.
        let mut undefined: Vec<Vec<u8>> = Vec::new();
        for sym in &ctx.symbols[scanned..] {
            if sym.is_undefined && !sym.name.is_empty() {
                undefined.push(sym.name.clone());
            }
        }
        scanned = ctx.symbols.len();
        if undefined.is_empty() {
            break;
        }
        // Reserve hits serially in name order so later picks observe the
        // reservations exactly as a serial extractor would.
        let mut work: Vec<(Vec<u8>, usize, usize)> = Vec::new();
        for name in &undefined {
            if let Some(&id) = ctx.symbol_map.get(name) {
                if !ctx.symbols[id].is_undefined {
                    continue;
                }
            }
            // Exact match first (static objects and thunks).
            let mut hit = pick(ctx, providers, name);
            // Then MinGW auto-import: an undefined data symbol `X` may be
            // satisfied by `__imp_X` from an import library.
            if hit.is_none() && !name.starts_with(b"__imp_") {
                let imp_name = [b"__imp_".as_slice(), name.as_slice()].concat();
                hit = pick(ctx, providers, &imp_name);
            }
            if let Some((ar_idx, m)) = hit {
                ctx.archives[ar_idx].members[m].extracted = true;
                work.push((name.clone(), ar_idx, m));
            }
        }
        if !extract_reserved(ctx, &work) {
            break;
        }
    }
}

/// Extracts every member of `--whole-archive` archives up front, mirroring
/// GNU ld. Members that are not COFF objects are skipped.
fn extract_whole_archives(ctx: &mut Context) {
    let wholes: Vec<usize> =
        ctx.archives.iter().enumerate().filter(|(_, ar)| ar.extract_all).map(|(i, _)| i).collect();
    for ar_idx in wholes {
        // Reserve the whole member list, then parse in parallel and merge
        // in member order.
        let mut work: Vec<(Vec<u8>, usize, usize)> = Vec::new();
        for m in 0..ctx.archives[ar_idx].members.len() {
            if ctx.archives[ar_idx].members[m].extracted {
                continue;
            }
            ctx.archives[ar_idx].members[m].extracted = true;
            // No triggering symbol (unconditional extraction); an empty
            // name never matches the symbol map, so merge commits it.
            work.push((Vec::new(), ar_idx, m));
        }
        extract_reserved(ctx, &work);
    }
}

/// Merges a freshly extracted archive member into the global symbol table
/// and registers `.idata` imports, mirroring the C++ driver's archive loop.
fn register_extracted_object(ctx: &mut Context, file_id: usize) {
    let is_import = input_files::is_import_member(&ctx.files[file_id]);
    if is_import {
        // Only `.idata` dies; the `.text` thunk stays live.
        for sec in ctx.files[file_id].sections.iter_mut() {
            if sec.name.starts_with(b".idata") {
                sec.is_alive = false;
            }
        }

        // Shared logic with direct import objects: pair each `.text`
        // thunk with its `.idata$6` import name.
        let mut imports = input_files::parse_import_entries(&ctx.files[file_id], &[]);
        // If the DLL name lives in a sibling member, hunt for it.
        if imports.iter().any(|i| i.dll_name.is_empty()) && !imports.is_empty() {
            if let Some(found) = find_sibling_dll_name(ctx, file_id) {
                for imp in imports.iter_mut() {
                    if imp.dll_name.is_empty() {
                        imp.dll_name = found.clone();
                    }
                }
            }
        }
        if !imports.is_empty() {
            // Map thunk names to their `.text` section in this member so
            // calls resolve to the thunk (which jumps through the IAT).
            use hashbrown::HashMap as Map;
            let mut thunk_sec: Map<Vec<u8>, (usize, u32)> = Map::new();
            for raw in &ctx.files[file_id].symbols {
                if raw.section_idx > 0
                    && (raw.section_idx as usize) <= ctx.files[file_id].sections.len()
                {
                    // Thunk symbols live in `.text`; `.idata` symbols are
                    // the `__imp_` pointers.
                    let sec = &ctx.files[file_id].sections[raw.section_idx as usize - 1];
                    if !sec.name.starts_with(b".idata") {
                        thunk_sec
                            .entry(raw.name.clone())
                            .or_insert((raw.section_idx as usize - 1, raw.value));
                    }
                }
            }
            // Register __imp_ + thunk symbols as defined imports. The
            // hint/name table uses the real import name (which may differ
            // from the thunk, e.g. `_set_app_type` vs `__set_app_type`).
            for imp in &imports {
                let imp_name = [b"__imp_".as_slice(), imp.symbol_name.as_slice()].concat();
                let id = ctx.get_or_intern(&imp_name);
                let sym = &mut ctx.symbols[id];
                sym.is_defined = true;
                sym.is_undefined = false;
                sym.is_imported = true;
                sym.is_dll_import = true;
                sym.dll_name = imp.dll_name.clone();
                sym.import_name = imp.import_name.clone();
                sym.ordinal_hint = imp.ordinal_hint;
                let id2 = ctx.get_or_intern(&imp.symbol_name);
                let sym2 = &mut ctx.symbols[id2];
                sym2.is_imported = true;
                sym2.is_dll_import = true;
                sym2.dll_name = imp.dll_name.clone();
                sym2.import_name = imp.import_name.clone();
                sym2.ordinal_hint = imp.ordinal_hint;
                if sym2.is_undefined {
                    if let Some(&(sidx, val)) = thunk_sec.get(&imp.symbol_name) {
                        sym2.section = Some(crate::context::SectionRef(file_id, sidx));
                        sym2.value = val;
                        sym2.is_defined = true;
                        sym2.is_undefined = false;
                        sym2.file = Some(file_id);
                    } else {
                        // No thunk (e.g. data import): defined via IAT.
                        sym2.is_defined = true;
                        sym2.is_undefined = false;
                    }
                }
            }
            let name = ctx.files[file_id].name.clone();
            ctx.import_objects.push(ImportObject { name, imports });
        }
    }

    let symbols = std::mem::take(&mut ctx.files[file_id].symbols);
    for raw in &symbols {
        if raw.name.is_empty() {
            continue;
        }
        // `_head_*` anchors name a DLL for import attribution (see
        // `iname_to_dll`); they are never defined and must not become
        // undefined references.
        if raw.name.starts_with(b"_head_") {
            continue;
        }
        if ctx.find(&raw.name).is_none() {
            let id = ctx.symbols.len();
            let absolute = raw.section_idx == crate::pe::IMAGE_SYM_ABSOLUTE as i32;
            let (defined, undefined, section) = if raw.section_idx > 0
                && (raw.section_idx as usize) <= ctx.files[file_id].sections.len()
            {
                (
                    true,
                    false,
                    Some(crate::context::SectionRef(file_id, (raw.section_idx - 1) as usize)),
                )
            } else if absolute {
                (true, false, None)
            } else {
                (false, true, None)
            };
            ctx.symbols.push(crate::context::Symbol {
                name: raw.name.clone(),
                value: raw.value,
                storage_class: raw.storage_class,
                is_weak: raw.is_weak,
                is_comdat: raw.is_comdat,
                is_defined: defined,
                is_undefined: undefined,
                is_imported: false,
                is_dll_import: false,
                is_exported: false,
                is_auto_imported: false,
                is_absolute: absolute,
                file: Some(file_id),
                section,
                resolved_value: if absolute { raw.value as u64 } else { 0 },
                dll_name: Vec::new(),
                import_name: Vec::new(),
                ordinal_hint: 0,
            });
            ctx.symbol_map.insert(raw.name.clone(), id);
        } else {
            let id = ctx.find(&raw.name).unwrap();
            if raw.section_idx > 0
                && (raw.section_idx as usize) <= ctx.files[file_id].sections.len()
            {
                let sym = &mut ctx.symbols[id];
                if sym.is_undefined {
                    sym.section =
                        Some(crate::context::SectionRef(file_id, (raw.section_idx - 1) as usize));
                    sym.value = raw.value;
                    sym.is_defined = true;
                    sym.is_undefined = false;
                    sym.file = Some(file_id);
                    sym.storage_class = raw.storage_class;
                }
            }
        }
    }
    ctx.files[file_id].symbols = symbols;
}

fn find_sibling_dll_name(ctx: &mut Context, file_id: usize) -> Option<Vec<u8>> {
    // Short-import members reference `_head_X` and leave `.idata$7` empty;
    // the DLL name string lives in the tail member defining the `iname`
    // anchor. Two spellings exist: MinGW short imports use `__X_iname`
    // (e.g. `__lib64_libkernel32_a_iname`) while dlltool libraries use
    // `X_iname` (e.g. `zlib1_dll_iname`).
    let inames: Vec<Vec<u8>> = ctx.files[file_id]
        .symbols
        .iter()
        .filter_map(|s| {
            s.name.strip_prefix(b"_head_").filter(|_| s.section_idx == 0).map(|x| x.to_vec())
        })
        .collect();
    let mut candidates: Vec<Vec<u8>> = Vec::new();
    for x in &inames {
        candidates.push([b"__".as_slice(), x, b"_iname".as_slice()].concat());
        candidates.push([x.as_slice(), b"_iname".as_slice()].concat());
    }

    // Ensure the owning archive's anchors are cached. The member's path
    // names its archive (`lib.a(member.o)`), so match by prefix.
    let file_name = ctx.files[file_id].name.clone();
    let mut order: Vec<usize> = (0..ctx.archives.len()).collect();
    order.sort_by_key(|&i| {
        !file_name
            .as_os_str()
            .as_encoded_bytes()
            .starts_with(ctx.archives[i].name.as_os_str().as_encoded_bytes())
    });
    for ar_idx in order {
        if ctx.iname_scanned.get(ar_idx).copied().unwrap_or(false) {
            continue;
        }
        scan_iname_anchors(ctx, ar_idx);
    }
    for iname in &candidates {
        if let Some(dll) = ctx.iname_to_dll.get(iname) {
            return Some(dll.clone());
        }
    }

    // Last resort: any data-bearing `.idata$7` in any archive.
    for ar in &ctx.archives {
        for m in &ar.members {
            let data = ar.mf.data();
            if m.offset + m.size > data.len() {
                continue;
            }
            let bytes = &data[m.offset..m.offset + m.size];
            if !crate::pe::is_coff_object(bytes) {
                continue;
            }
            let Some(hdr) = crate::pe::CoffHeader::parse(bytes) else { continue };
            let n = hdr.num_sections as usize;
            if 20 + n * 40 > bytes.len() {
                continue;
            }
            for i in 0..n {
                let off = 20 + i * 40;
                let Some(sh) = crate::pe::SectionHeader::parse(&bytes[off..off + 40]) else {
                    continue;
                };
                let len = sh.name.iter().position(|&c| c == 0).unwrap_or(8);
                if &sh.name[..len] != b".idata$7" || sh.raw_data_size == 0 {
                    continue;
                }
                let s = sh.raw_data_ptr as usize;
                let e = s + sh.raw_data_size as usize;
                if e > bytes.len() {
                    continue;
                }
                if bytes[s..e].iter().any(|&c| c != 0) {
                    let _ = &file_name;
                    return Some(crate::pe::cstr_at(&bytes[s..e]).to_vec());
                }
            }
        }
    }
    None
}

/// Records every `__X_iname` anchor of an archive and the DLL name in its
/// `.idata$7`: tail members (e.g. `libkernel32t.o`) hold the file name
/// (`KERNEL32.dll`) that short-import members' empty `.idata$7` omits.
fn scan_iname_anchors(ctx: &mut Context, ar_idx: usize) {
    while ctx.iname_scanned.len() <= ar_idx {
        ctx.iname_scanned.push(false);
    }
    if ctx.iname_scanned[ar_idx] {
        return;
    }
    ctx.iname_scanned[ar_idx] = true;

    let mf = ctx.archives[ar_idx].mf;
    let data = mf.data();
    let members: Vec<(usize, usize)> =
        ctx.archives[ar_idx].members.iter().map(|m| (m.offset, m.size)).collect();
    for (offset, size) in members {
        if offset + size > data.len() || !crate::pe::is_coff_object(&data[offset..offset + size]) {
            continue;
        }
        let bytes = &data[offset..offset + size];
        let Some(hdr) = crate::pe::CoffHeader::parse(bytes) else { continue };
        let n = hdr.num_sections as usize;
        if 20 + n * 40 > bytes.len() {
            continue;
        }
        // DLL name from a data-bearing `.idata$7`.
        let mut dll: Option<&[u8]> = None;
        for i in 0..n {
            let off = 20 + i * 40;
            let Some(sh) = crate::pe::SectionHeader::parse(&bytes[off..off + 40]) else { continue };
            let len = sh.name.iter().position(|&c| c == 0).unwrap_or(8);
            if &sh.name[..len] != b".idata$7" || sh.raw_data_size == 0 {
                continue;
            }
            let s = sh.raw_data_ptr as usize;
            let e = s + sh.raw_data_size as usize;
            if e > bytes.len() {
                continue;
            }
            if bytes[s..e].iter().any(|&c| c != 0) {
                dll = Some(crate::pe::cstr_at(&bytes[s..e]));
                break;
            }
        }
        let Some(dll) = dll else { continue };
        // Anchor symbols ending in `_iname` (e.g. `__lib64_libkernel32_a_iname`).
        let symoff = hdr.symtab_offset as usize;
        let nsym = hdr.num_symbols as usize;
        if symoff + nsym * 18 > bytes.len() {
            continue;
        }
        let strtab_off = symoff + nsym * 18;
        if strtab_off + 4 > bytes.len() {
            continue;
        }
        let strsz =
            u32::from_le_bytes(bytes[strtab_off..strtab_off + 4].try_into().unwrap()) as usize;
        if strtab_off + strsz > bytes.len() {
            continue;
        }
        let strtab = &bytes[strtab_off..strtab_off + strsz];
        let mut i = 0;
        while i < nsym {
            let o = symoff + i * 18;
            let class = bytes[o + 16];
            let name: Vec<u8> = if &bytes[o..o + 4] == b"\x00\x00\x00\x00" {
                let so = u32::from_le_bytes(bytes[o + 4..o + 8].try_into().unwrap()) as usize;
                if so < strtab.len() {
                    crate::pe::cstr_at(&strtab[so..]).to_vec()
                } else {
                    Vec::new()
                }
            } else {
                let end = bytes[o..o + 8].iter().position(|&c| c == 0).unwrap_or(8);
                bytes[o..o + end].to_vec()
            };
            let naux = bytes[o + 17];
            if class == crate::pe::IMAGE_SYM_CLASS_EXTERNAL && name.ends_with(b"_iname") {
                ctx.iname_to_dll.entry(name).or_insert_with(|| dll.to_vec());
            }
            i += 1 + naux as usize;
        }
    }
}

pub fn link(cmdline: Cmdline) {
    mold_common::error::install_panic_hook();
    let parsed = parse_args(&cmdline);
    if parsed.input_files.is_empty() && parsed.libraries.is_empty() {
        fatal!("no input files");
    }

    let mut ctx = Context::default();
    ctx.args = parsed.args;
    ctx.args.chroot = PathBuf::new();

    // Wave 1: open and parse direct inputs in parallel (like the ELF
    // reader); the ordered collect restores command-line order for the
    // serial merge, keeping file priorities deterministic.
    let input_jobs: Vec<(PathBuf, bool)> = parsed
        .input_files
        .into_iter()
        .enumerate()
        .map(|(n, path)| (path, parsed.input_whole.get(n).copied().unwrap_or(false)))
        .collect();
    let input_outcomes: Vec<(ReadOutcome, bool)> = {
            let ctx_ref: &Context = &ctx;
        input_jobs
            .into_par_iter()
            .map(|(path, whole)| {
                let mf = must_open_file(&ctx_ref.args.chroot, &path);
                (read_input_file(mf), whole)
            })
            .collect()
    };
    for (outcome, whole) in input_outcomes {
        commit_read(&mut ctx, outcome, whole);
    }
    // Wave 2: `-l` libraries, now that direct objects have fixed the
    // target architecture for sysroot preference and arch checks.
    let lib_jobs: Vec<(OsString, bool)> = parsed
        .libraries
        .into_iter()
        .enumerate()
        .map(|(n, name)| (name, parsed.library_whole.get(n).copied().unwrap_or(false)))
        .collect();
    let lib_outcomes: Vec<(Option<ReadOutcome>, OsString, bool)> = {
            let ctx_ref: &Context = &ctx;
        lib_jobs
            .into_par_iter()
            .map(|(name, whole)| {
                let outcome = match find_library(ctx_ref, &name) {
                    Some(path) => open_file(&ctx_ref.args.chroot, &path).map(read_input_file),
                    None => None,
                };
                (outcome, name, whole)
            })
            .collect()
    };
    for (outcome, name, whole) in lib_outcomes {
        match outcome {
            Some(outcome) => commit_read(&mut ctx, outcome, whole),
            None => error!("cannot find library: {}", name.to_string_lossy()),
        }
    }
    // Merge the per-archive symbol indexes into one global provider index.
    // Keys are moved (not cloned) out of the archive maps, which nothing
    // reads afterwards; each name maps to its candidate members in archive
    // order, so one hash lookup replaces a scan over all archives.
    let providers: hashbrown::HashMap<Vec<u8>, Vec<(usize, usize)>> = {
        let total: usize = ctx.archives.iter().map(|ar| ar.symbol_to_member.len()).sum();
        let mut providers = hashbrown::HashMap::with_capacity(total);
        for (ar_idx, ar) in ctx.archives.iter_mut().enumerate() {
            for (name, m) in std::mem::take(&mut ar.symbol_to_member) {
                providers.entry(name).or_insert_with(Vec::new).push((ar_idx, m));
            }
        }
        providers
    };
    crate::passes::collect_symbols(&mut ctx);
    extract_whole_archives(&mut ctx);
    crate::passes::resolve_import_symbols(&mut ctx);
    resolve_from_archives(&mut ctx, &providers);
    if ctx.files.is_empty() {
        fatal!("no input objects");
    }
    crate::passes::resolve_import_symbols(&mut ctx);
    crate::passes::handle_auto_imports(&mut ctx);
    crate::passes::run_linking_passes(&mut ctx);
    crate::writer::write_output(&mut ctx);

    // No `drop_mappings`: unlike the ELF linker, PE never rewrites input
    // mappings in place, so there is nothing to discard; the kernel
    // reclaims the mappings on exit faster than hundreds of per-member
    // `MADV_DONTNEED` calls.
}

/// Whether the command line asks for a PE target (`-m i386pep`,
/// `-m pe-coff-x86-64`, `--subsystem`, `--dll`, ...).
pub fn wants_pe_target(argv: &[OsString]) -> bool {
    let mut iter = argv.iter().peekable();
    while let Some(arg) = iter.next() {
        let b = arg.as_encoded_bytes();
        if b == b"-m" || b == b"--emulation" {
            if let Some(v) = iter.next() {
                let v = v.as_encoded_bytes();
                if v == b"i386pep" || v == b"pe-coff-x86-64" || v == b"pe-x86-64" {
                    return true;
                }
                if v == b"arm64pep" || v == b"pe-coff-aarch64" || v == b"pe-aarch64" {
                    return true;
                }
            }
        } else if b.starts_with(b"-m") && b.len() > 2 {
            // -mi386pep form is not standard; ignore.
        } else if b == b"--dll"
            || b == b"--shared"
            || b == b"--export-all-symbols"
            || b == b"--subsystem"
            || b.starts_with(b"--subsystem=")
            || b == b"--image-base"
            || b.starts_with(b"--image-base=")
            || b == b"--enable-auto-import"
            || b == b"--disable-auto-import"
            || b == b"--out-implib"
            || b.starts_with(b"--out-implib=")
            || b == b"--output-def"
            || b.starts_with(b"--output-def=")
            || b == b"--major-image-version"
            || b.starts_with(b"--major-image-version=")
            || b == b"--minor-image-version"
            || b.starts_with(b"--minor-image-version=")
            || b == b"--stack"
            || b.starts_with(b"--stack=")
            || b == b"--heap"
            || b.starts_with(b"--heap=")
            || b == b"--enable-stdcall-fixup"
            || b == b"--disable-stdcall-fixup"
            || b == b"--enable-auto-image-base"
            || b == b"--disable-auto-image-base"
        {
            return true;
        }
    }
    false
}

/// Detects a PE target from input files for `-m`-less dispatch.
/// Response files are expanded (best effort) so that objects and import
/// libraries passed via `@file.rsp` are seen too.
pub fn detect_pe_target(argv: &[OsString]) -> Option<&'static str> {
    let mut cands: Vec<&OsStr> = Vec::new();
    for arg in argv.iter().skip(1) {
        let b = arg.as_encoded_bytes();
        if let Some(rest) = b.strip_prefix(b"@") {
            if !rest.is_empty() {
                cands.extend(rsp_candidates(Path::new(OsStr::from_bytes(rest))));
            }
            continue;
        }
        cands.push(arg.as_os_str());
    }
    let mut seen_coff = false;
    for cand in cands {
        if cand.as_encoded_bytes().starts_with(b"-") {
            continue;
        }
        let path = Path::new(cand);
        // Only regular files can be COFF inputs; probing anything else
        // (e.g. --chroot roots, -C or -rpath directories) must not fail
        // the link, since open() succeeds on directories but mmap() does
        // not, which open_file reports as fatal.
        if std::fs::metadata(path).is_ok_and(|md| !md.is_file()) {
            continue;
        }
        let Some(mf) = open_file(Path::new(""), path) else {
            continue;
        };
        match get_file_type(mf) {
            FileType::CoffObj | FileType::PeFile => {
                seen_coff = true;
                if let Some(t) = get_pe_target(mf.data()) {
                    return Some(t);
                }
            }
            FileType::CoffArchive => {
                seen_coff = true;
                if let Some(t) = archive_pe_target(mf.data()) {
                    return Some(t);
                }
            }
            _ => continue,
        }
    }
    // COFF input of unknown arch (e.g. an archive with no object members
    // yet examined): still a PE link.
    if seen_coff {
        return Some("pe-x86-64");
    }
    None
}

/// Best-effort tokenization of a response file for target detection.
/// Never fails; unreadable files yield no candidates.
fn rsp_candidates(path: &Path) -> Vec<&'static OsStr> {
    // Leak the bytes so the returned slices are 'static. Detection runs
    // once per process; the amount of data is bounded by the rsp file.
    fn leak(data: Vec<u8>) -> &'static [u8] {
        Box::leak(data.into_boxed_slice())
    }
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    let bytes: &'static [u8] = leak(bytes);
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let mut tok = Vec::new();
        let mut quote = 0u8;
        while i < bytes.len() {
            let c = bytes[i];
            if quote != 0 {
                if c == quote {
                    quote = 0;
                } else if c == b'\\' && i + 1 < bytes.len() {
                    i += 1;
                    tok.push(bytes[i]);
                } else {
                    tok.push(c);
                }
                i += 1;
            } else if c == b'\'' || c == b'"' {
                quote = c;
                i += 1;
            } else if c == b'\\' && i + 1 < bytes.len() {
                i += 1;
                tok.push(bytes[i]);
                i += 1;
            } else if c.is_ascii_whitespace() {
                break;
            } else {
                tok.push(c);
                i += 1;
            }
        }
        if !tok.is_empty() {
            out.push(OsStr::from_bytes(leak(tok)));
        }
    }
    out
}

/// Target of a SysV archive from its first object-like member. Special
/// members (linker map `/`, string table `//`, `__.SYMDEF`) are skipped;
/// both regular objects and short-import members start with the COFF
/// machine field.
fn archive_pe_target(data: &[u8]) -> Option<&'static str> {
    if data.len() < 8 || &data[..8] == b"!<thin>\n" {
        return None;
    }
    if &data[..8] != b"!<arch>\n" {
        return None;
    }
    let mut off = 8usize;
    while off + 60 <= data.len() {
        let hdr = &data[off..off + 60];
        let name = &hdr[..16];
        let mut end = name.len();
        while end > 0 && (name[end - 1] == b' ' || name[end - 1] == 0) {
            end -= 1;
        }
        let name = &name[..end];
        let size: usize = std::str::from_utf8(&hdr[48..58]).ok()?.trim().parse().ok()?;
        off += 60;
        if off + size > data.len() {
            return None;
        }
        let special = name == b"/" || name == b"//" || name == b"__.SYMDEF" || name == b"/SYM64/";
        if !special && size >= 2 {
            let machine = u16::from_le_bytes([data[off], data[off + 1]]);
            // BigObj members start with the anon header, not the machine.
            if machine == 0 && size >= 8 {
                return match u16::from_le_bytes([data[off + 6], data[off + 7]]) {
                    crate::pe::COFF_MACHINE_AMD64 => Some("pe-x86-64"),
                    crate::pe::COFF_MACHINE_ARM64 => Some("pe-aarch64"),
                    _ => None,
                };
            }
            return match machine {
                crate::pe::COFF_MACHINE_AMD64 => Some("pe-x86-64"),
                crate::pe::COFF_MACHINE_ARM64 => Some("pe-aarch64"),
                crate::pe::COFF_MACHINE_I386 => Some("pe-i386"),
                _ => None,
            };
        }
        off += (size + 1) & !1;
    }
    None
}

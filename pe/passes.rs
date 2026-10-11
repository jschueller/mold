//! Symbol resolution, section merging and table building.
//!
//! Ported from `src/pe-coff/passes.cc` and `src/pe-coff/auto-export.cc`
//! (the latter also lives in `auto_export.rs`; this module wires it in).

use mold_common::warn;

use crate::auto_export::collect_auto_exports;
use crate::context::{Context, SectionRef};
use crate::pe::{
    IMAGE_SCN_CNT_CODE, IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA,
    IMAGE_SCN_MEM_DISCARDABLE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
    IMAGE_SYM_CLASS_EXTERNAL, IMAGE_SYM_CLASS_WEAK_EXTERNAL,
};

pub fn collect_symbols(ctx: &mut Context) {
    for file_id in 0..ctx.files.len() {
        // Move the vec out instead of cloning: the loop also pushes to the
        // global table, which conflicts with an outstanding borrow.
        let symbols = std::mem::take(&mut ctx.files[file_id].symbols);
        for raw in &symbols {
            if raw.name.is_empty() {
                continue;
            }
            if ctx.find(&raw.name).is_none() {
                let id = ctx.symbols.len();
                // Absolute symbols (section -1) are already VAs.
                let absolute = raw.section_idx == crate::pe::IMAGE_SYM_ABSOLUTE as i32;
                let (defined, undefined, section) = if raw.section_idx > 0 {
                    let sidx = (raw.section_idx - 1) as usize;
                    if sidx < ctx.files[file_id].sections.len() {
                        (true, false, Some(SectionRef(file_id, sidx)))
                    } else {
                        (false, true, None)
                    }
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
                continue;
            }
            let id = ctx.find(&raw.name).unwrap();
            let defined_here = raw.section_idx > 0
                && (raw.section_idx as usize) <= ctx.files[file_id].sections.len();
            if defined_here {
                let sidx = (raw.section_idx - 1) as usize;
                let sym = &mut ctx.symbols[id];
                if sym.is_undefined {
                    sym.section = Some(SectionRef(file_id, sidx));
                    sym.value = raw.value;
                    sym.is_defined = true;
                    sym.is_undefined = false;
                    sym.file = Some(file_id);
                    sym.storage_class = raw.storage_class;
                } else if sym.is_defined {
                    if sym.is_weak && !raw.is_weak {
                        sym.section = Some(SectionRef(file_id, sidx));
                        sym.value = raw.value;
                        sym.file = Some(file_id);
                        sym.is_weak = false;
                    } else if !sym.is_weak && !raw.is_weak && !sym.is_comdat && !raw.is_comdat {
                        warn!(
                            "multiple definition of symbol: {}",
                            String::from_utf8_lossy(&sym.name)
                        );
                    }
                }
            }
        }
        ctx.files[file_id].symbols = symbols;
    }
}

pub fn resolve_import_symbols(ctx: &mut Context) {
    let imports: Vec<_> = ctx.import_objects.iter().flat_map(|o| o.imports.clone()).collect();
    for imp in imports {
        let imp_name = [b"__imp_".as_slice(), &imp.symbol_name].concat();
        let id = ctx.get_or_intern(&imp_name);
        let sym = &mut ctx.symbols[id];
        if sym.is_undefined {
            sym.is_defined = true;
            sym.is_undefined = false;
            sym.is_imported = true;
            sym.is_dll_import = true;
            sym.dll_name = imp.dll_name.clone();
            sym.import_name = imp.import_name.clone();
            sym.ordinal_hint = imp.ordinal_hint;
        }
        let id2 = ctx.get_or_intern(&imp.symbol_name);
        let sym2 = &mut ctx.symbols[id2];
        if sym2.is_undefined {
            sym2.is_defined = true;
            sym2.is_undefined = false;
            sym2.is_imported = true;
            sym2.is_dll_import = true;
            sym2.dll_name = imp.dll_name.clone();
            sym2.import_name = imp.import_name.clone();
            sym2.ordinal_hint = imp.ordinal_hint;
        }
    }
}

fn should_auto_import(ctx: &Context, id: usize) -> bool {
    if !ctx.args.enable_auto_import {
        return false;
    }
    let sym = &ctx.symbols[id];
    if !sym.is_undefined {
        return false;
    }
    let imp_name = [b"__imp_".as_slice(), sym.name.as_slice()].concat();
    match ctx.find(&imp_name) {
        Some(imp) => ctx.symbols[imp].is_defined,
        None => false,
    }
}

pub fn handle_auto_imports(ctx: &mut Context) {
    if !ctx.args.enable_auto_import {
        return;
    }
    let mut todo = Vec::new();
    for (id, sym) in ctx.symbols.iter().enumerate() {
        if sym.is_undefined && !sym.name.is_empty() {
            let imp_name = [b"__imp_".as_slice(), sym.name.as_slice()].concat();
            if let Some(imp) = ctx.find(&imp_name) {
                if ctx.symbols[imp].is_defined {
                    todo.push((id, imp));
                }
            }
        }
    }
    for (id, imp) in todo {
        let (section, value, resolved) = {
            let s = &ctx.symbols[imp];
            (s.section, s.value, s.resolved_value)
        };
        let sym = &mut ctx.symbols[id];
        sym.is_defined = true;
        sym.is_undefined = false;
        sym.is_auto_imported = true;
        sym.is_imported = true;
        sym.section = section;
        sym.value = value;
        sym.resolved_value = resolved;
    }
    let _ = should_auto_import;
}

pub fn select_comdat(ctx: &mut Context) {
    use hashbrown::HashMap;
    let mut seen: HashMap<Vec<u8>, SectionRef> = HashMap::new();
    for file_id in 0..ctx.files.len() {
        for sec_idx in 0..ctx.files[file_id].sections.len() {
            if !ctx.files[file_id].sections[sec_idx].is_comdat {
                continue;
            }
            // Borrowed lookup; clone only on first sight.
            let name = &ctx.files[file_id].sections[sec_idx].name;
            if seen.contains_key(name.as_slice()) {
                ctx.files[file_id].sections[sec_idx].is_alive = false;
            } else {
                seen.insert(name.clone(), SectionRef(file_id, sec_idx));
            }
        }
    }
}

pub fn create_output_sections(ctx: &mut Context) {
    for file_id in 0..ctx.files.len() {
        // Import-membership is per file (name-based, unaffected by the
        // liveness kills below); hoist out of the section loop.
        let file_is_import = crate::input_files::is_import_member(&ctx.files[file_id]);
        for sec_idx in 0..ctx.files[file_id].sections.len() {
            if !ctx.files[file_id].sections[sec_idx].is_alive {
                continue;
            }
            // Skip import-library pseudo-sections; the writer synthesizes
            // `.idata` from the import table.
            if file_is_import && ctx.files[file_id].sections[sec_idx].name.starts_with(b".idata") {
                ctx.files[file_id].sections[sec_idx].is_alive = false;
                continue;
            }
            let chars = ctx.files[file_id].sections[sec_idx].characteristics;
            // Borrowed map probe first: output sections are few and repeat
            // constantly, so this avoids a `to_vec` per input section.
            // The characteristics accumulation (`|=`) still happens on
            // every hit, exactly as `get_or_create_output_section` does.
            let out_id = {
                let prefix = crate::pe::section_prefix(&ctx.files[file_id].sections[sec_idx].name);
                if let Some(&id) = ctx.output_section_map.get(prefix) {
                    ctx.output_sections[id].characteristics |= chars;
                    id
                } else {
                    // Miss: copy the name (rare) so the map insert can
                    // take `&mut ctx`.
                    let owned = prefix.to_vec();
                    ctx.get_or_create_output_section(&owned, chars)
                }
            };
            ctx.files[file_id].sections[sec_idx].output_section = Some(out_id);
            ctx.output_sections[out_id].inputs.push(SectionRef(file_id, sec_idx));
        }
    }

    ctx.text_section = Some(ctx.get_or_create_output_section(
        b".text",
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
    ));
    ctx.rdata_section = Some(ctx.get_or_create_output_section(
        b".rdata",
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
    ));
    ctx.data_section = Some(ctx.get_or_create_output_section(
        b".data",
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
    ));
    ctx.bss_section = Some(ctx.get_or_create_output_section(
        b".bss",
        IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
    ));
    ctx.idata_section = Some(ctx.get_or_create_output_section(
        b".idata",
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
    ));
    if ctx.args.is_dll || !ctx.args.exports.is_empty() || ctx.args.export_all_symbols {
        ctx.edata_section = Some(ctx.get_or_create_output_section(
            b".edata",
            IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        ));
    }
    ctx.reloc_section = Some(ctx.get_or_create_output_section(
        b".reloc",
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_DISCARDABLE,
    ));

    // Order inputs within each output section by `$` suffix, as GNU ld
    // does: `.CRT$XCA` anchors precede `.CRT$XCU` initializers which
    // precede `.CRT$XCZ`, so `__xc_a < __xc_z`. Sections without a suffix
    // sort first; ties keep link order (stable sort). `.ctors.65535`
    // (crtend's terminator registrar) sorts after plain `.ctors` so
    // initializers run before it; same for `.dtors`. Keys borrow the
    // section names (one suffix computation per input, no allocation).
    for out_id in 0..ctx.output_sections.len() {
        let out_name = ctx.output_sections[out_id].name.clone();
        let grouped = out_name == b".ctors" || out_name == b".dtors";
        let inputs = std::mem::take(&mut ctx.output_sections[out_id].inputs);
        let mut order: Vec<(&[u8], usize)> = inputs
            .iter()
            .enumerate()
            .map(|(pos, &r)| {
                let sec_name = ctx.files[r.0].sections[r.1].name.as_slice();
                let key = if grouped && sec_name != out_name.as_slice() {
                    sec_name
                } else {
                    crate::pe::section_suffix(sec_name)
                };
                (key, pos)
            })
            .collect();
        order.sort_by(|a, b| a.0.cmp(b.0));
        // End the name borrows before taking `&mut ctx` again.
        let sorted: Vec<SectionRef> = order.iter().map(|&(_, p)| inputs[p]).collect();
        ctx.output_sections[out_id].inputs = sorted;
    }
}

pub fn build_import_table(ctx: &mut Context) {
    use hashbrown::HashMap;
    let mut by_dll: HashMap<Vec<u8>, Vec<usize>> = HashMap::new();
    for (id, sym) in ctx.symbols.iter().enumerate() {
        if !sym.is_dll_import || sym.name.starts_with(b"__imp_") {
            continue;
        }
        by_dll.entry(sym.dll_name.clone()).or_default().push(id);
    }
    let mut dlls: Vec<_> = by_dll.into_iter().collect();
    dlls.sort_by(|a, b| a.0.cmp(&b.0));
    for (dll_name, mut ids) in dlls {
        ids.sort_by(|&a, &b| ctx.symbols[a].name.cmp(&ctx.symbols[b].name));
        ctx.import_dlls.push(crate::context::ImportDll { dll_name, entries: ids });
    }
}

pub fn build_export_table(ctx: &mut Context) {
    // DLLs auto-export all globals by default (GNU ld behavior);
    // executables only with an explicit `--export-all-symbols`.
    let auto = ctx.args.export_all_symbols && (ctx.args.is_dll || ctx.args.export_all_explicit);
    if !ctx.args.is_dll && ctx.args.exports.is_empty() && !auto {
        return;
    }
    for exp in ctx.args.exports.clone() {
        if let Some(id) = ctx.find(&exp) {
            ctx.export_names.push((exp, id));
            ctx.symbols[id].is_exported = true;
        } else {
            warn!("export symbol not found: {}", String::from_utf8_lossy(&exp));
        }
    }
    if ctx.args.export_all_symbols && (ctx.args.is_dll || ctx.args.export_all_explicit) {
        for (name, id) in collect_auto_exports(ctx) {
            if ctx.symbols[id].is_exported {
                continue;
            }
            ctx.symbols[id].is_exported = true;
            ctx.export_names.push((name, id));
        }
    }
    if !ctx.export_names.is_empty() {
        let mut dll_name = ctx.args.output.as_os_str().as_encoded_bytes().to_vec();
        if let Some(pos) = dll_name.iter().rposition(|&c| c == b'.') {
            let ext = &dll_name[pos..];
            if ext.eq_ignore_ascii_case(b".dll") || ext.eq_ignore_ascii_case(b".exe") {
                dll_name.truncate(pos);
            }
        }
        // Keep only the file name for the export directory.
        if let Some(pos) = dll_name.iter().rposition(|&c| c == b'/' || c == b'\\') {
            dll_name = dll_name[pos + 1..].to_vec();
        }
        ctx.export_dll_name = dll_name;
        ctx.export_names.sort_by(|a, b| a.0.cmp(&b.0));
    }
}

pub fn resolve_entry_point(ctx: &mut Context) {
    if !ctx.args.entry.is_empty() {
        let entry = ctx.args.entry.clone();
        match ctx.find(&entry) {
            Some(id) if ctx.symbols[id].is_defined => {
                ctx.entry_symbol = Some(id);
            }
            _ => {
                mold_common::fatal!("undefined entry point: {}", String::from_utf8_lossy(&entry));
            }
        }
    } else {
        // MinGW startup: crt2.o provides `mainCRTStartup` /
        // `WinMainCRTStartup` (selected by subsystem), which runs global
        // initializers and then calls `main` / `WinMain`. Bare object
        // files without the CRT fall back to `main` itself.
        let candidates: &[&[u8]] = if ctx.args.is_dll {
            &[]
        } else if ctx.args.subsystem == crate::pe::IMAGE_SUBSYSTEM_WINDOWS_GUI {
            &[
                b"WinMainCRTStartup",
                b"wWinMainCRTStartup",
                b"WinMain",
                b"wWinMain",
                b"mainCRTStartup",
                b"main",
            ]
        } else {
            &[
                b"mainCRTStartup",
                b"wmainCRTStartup",
                b"main",
                b"wmain",
                b"WinMainCRTStartup",
                b"WinMain",
            ]
        };
        let mut found = None;
        for cand in candidates {
            if let Some(id) = ctx.find(cand) {
                if ctx.symbols[id].is_defined {
                    found = Some(id);
                    break;
                }
            }
            // MinGW prepends '_' to some entry symbols.
            let underscored = [b"_".as_slice(), *cand].concat();
            if let Some(id) = ctx.find(&underscored) {
                if ctx.symbols[id].is_defined {
                    found = Some(id);
                    break;
                }
            }
        }
        // CRT entry points used by mingw drivers.
        if found.is_none() {
            for cand in
                [b"mainCRTStartup".as_slice(), b"WinMainCRTStartup".as_slice(), b"_main".as_slice()]
            {
                if let Some(id) = ctx.find(cand) {
                    if ctx.symbols[id].is_defined {
                        found = Some(id);
                        break;
                    }
                }
            }
        }
        if let Some(id) = found {
            ctx.entry_symbol = Some(id);
        } else if ctx.args.is_dll {
            ctx.entry_point_rva = 0;
            return;
        } else {
            mold_common::fatal!("entry point not found");
        }
    }
    if let Some(id) = ctx.entry_symbol {
        ctx.entry_point_rva = ctx.symbols[id].resolved_value;
    }
}

pub fn assign_symbol_addresses(ctx: &mut Context) {
    for sym in ctx.symbols.iter_mut() {
        if !sym.is_defined {
            continue;
        }
        if let Some(r) = sym.section {
            let sec = &ctx.files[r.0].sections[r.1];
            sym.resolved_value = sec.rva + sym.value as u64;
        }
    }
    // IAT-backed `__imp_` symbols point into the synthesized `.idata`.
    if let Some(idata) = ctx.idata_section {
        if !ctx.import_dlls.is_empty() {
            let idata_rva = ctx.output_sections[idata].rva;
            let (_, iat_rva, _, _) = crate::writer::import_table_rvas(ctx, idata_rva);
            let mut slot_rva = iat_rva;
            // Map thunk symbol -> IAT slot.
            use hashbrown::HashMap;
            let mut slot_of: HashMap<usize, u64> = HashMap::new();
            for dll in &ctx.import_dlls {
                for (j, &id) in dll.entries.iter().enumerate() {
                    slot_of.insert(id, slot_rva + j as u64 * 8);
                }
                slot_rva += (dll.entries.len() + 1) as u64 * 8;
            }
            for id in 0..ctx.symbols.len() {
                if !ctx.symbols[id].is_dll_import {
                    continue;
                }
                let name = ctx.symbols[id].name.clone();
                if let Some(rest) = name.strip_prefix(b"__imp_") {
                    if let Some(&thunk) = ctx.symbol_map.get(rest) {
                        if let Some(&slot) = slot_of.get(&thunk) {
                            let sym = &mut ctx.symbols[id];
                            sym.resolved_value = slot;
                            sym.section = None;
                            sym.is_defined = true;
                            sym.is_undefined = false;
                            // Pure data imports have no `.text` thunk: the
                            // thunk-named symbol aliases the IAT slot itself
                            // (MinGW auto-import), so point it there too.
                            // Code thunks keep their own address.
                            if ctx.symbols[thunk].section.is_none() {
                                ctx.symbols[thunk].resolved_value = slot;
                            }
                        }
                    }
                }
            }
        }
    }
    // Auto-imported data symbols alias their `__imp_` slot, finalized above.
    for id in 0..ctx.symbols.len() {
        if !ctx.symbols[id].is_auto_imported {
            continue;
        }
        let imp_name = [b"__imp_".as_slice(), ctx.symbols[id].name.as_slice()].concat();
        if let Some(imp) = ctx.find(&imp_name) {
            let slot = ctx.symbols[imp].resolved_value;
            if slot != 0 {
                let sym = &mut ctx.symbols[id];
                sym.section = None;
                sym.value = 0;
                sym.resolved_value = slot;
            }
        }
    }
    let image_base = ctx.args.image_base;
    for name in
        [b"__ImageBase".as_slice(), b"__ImageBase16".as_slice(), b"__ImageBase32".as_slice()]
    {
        if let Some(id) = ctx.find(name) {
            if !ctx.symbols[id].is_defined {
                let sym = &mut ctx.symbols[id];
                sym.is_defined = true;
                sym.is_undefined = false;
                sym.is_absolute = true;
                sym.resolved_value = image_base;
            }
        }
    }
}

/// Size of the `-1` sentinel prepended to a `.ctors`/`.dtors` output
/// section, or 0 when the first input already provides one (old-style
/// crtbegin). `__do_global_ctors` treats a leading `-1` as an old-format
/// list and scans for the `0` terminator; without it the first entry
/// would be misread as an entry count.
pub fn ctor_head_size(ctx: &Context, out_id: usize) -> u64 {
    let name = ctx.output_sections[out_id].name.clone();
    if name != b".ctors" && name != b".dtors" {
        return 0;
    }
    for &r in &ctx.output_sections[out_id].inputs {
        let sec = &ctx.files[r.0].sections[r.1];
        if !sec.is_alive || sec.contents.len() < 8 {
            continue;
        }
        if sec.relocs.iter().any(|rel| (rel.virtual_address as usize) < 8) {
            return 8;
        }
        return if sec.contents[..8] == [0xff; 8] { 0 } else { 8 };
    }
    8
}

/// Define `__CTOR_LIST__`/`__DTOR_LIST__` (plus `___` aliases) at the
/// start of the framed `.ctors`/`.dtors` outputs so libgcc `__main` finds
/// the static initializers. Without these the symbols resolve to libgcc's
/// zero commons and constructors silently never run.
pub fn build_ctor_lists(ctx: &mut Context) {
    let pairs: &[(&[u8], &[u8], &[u8])] = &[
        (b".ctors", b"__CTOR_LIST__", b"___CTOR_LIST__"),
        (b".dtors", b"__DTOR_LIST__", b"___DTOR_LIST__"),
    ];
    for (sec_name, list, list_alias) in pairs {
        let Some(&id) = ctx.output_section_map.get(*sec_name) else {
            continue;
        };
        let rva = ctx.output_sections[id].rva;
        for name in [*list, *list_alias] {
            let sym_id = ctx.get_or_intern(name);
            let sym = &mut ctx.symbols[sym_id];
            sym.is_defined = true;
            sym.is_undefined = false;
            sym.section = None;
            sym.value = 0;
            sym.resolved_value = rva;
        }
    }
}

pub fn run_linking_passes(ctx: &mut Context) {
    // The file/symbol sets are final now; snapshot global ids so the
    // relocation-heavy passes below avoid a hash lookup per site.
    crate::relocations::build_id_cache(ctx);
    select_comdat(ctx);
    // GC is a no-op placeholder unless requested; keep all sections alive
    // by default to match the prototype's behavior for hello-world links.
    create_output_sections(ctx);
    build_import_table(ctx);
    build_export_table(ctx);
    crate::output::calculate_layout(ctx);
    assign_symbol_addresses(ctx);
    // Runtime pseudo-relocs need final addresses, but reserving the list
    // blob can shift `.idata`; the item count is layout-independent, so one
    // layout/build round-trip converges.
    crate::pseudo_reloc::build(ctx);
    crate::output::calculate_layout(ctx);
    assign_symbol_addresses(ctx);
    crate::pseudo_reloc::build(ctx);
    build_ctor_lists(ctx);
    resolve_entry_point(ctx);
    // Base relocations need final RVAs; sizing `.reloc` can shift sections
    // laid out after it, so iterate to a fixpoint (converges at once when
    // `.reloc` is last).
    for _ in 0..4 {
        crate::relocations::collect_base_relocs(ctx);
        let changed = crate::output::size_reloc_section(ctx);
        crate::output::calculate_layout(ctx);
        crate::relocations::collect_base_relocs(ctx);
        if crate::output::size_reloc_section(ctx) == changed && !changed {
            break;
        }
    }
    let _ = IMAGE_SYM_CLASS_EXTERNAL;
    let _ = IMAGE_SYM_CLASS_WEAK_EXTERNAL;
}

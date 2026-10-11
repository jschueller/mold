//! COFF relocation application for x86-64.
//!
//! Ported from `src/pe-coff/relocations.cc`.

use std::collections::BTreeMap;

use mold_common::{error, warn};
use rayon::prelude::*;

use crate::context::{Context, SectionRef};
use crate::pe::{
    IMAGE_REL_AMD64_ABSOLUTE, IMAGE_REL_AMD64_ADDR32, IMAGE_REL_AMD64_ADDR32NB,
    IMAGE_REL_AMD64_ADDR64, IMAGE_REL_AMD64_REL32, IMAGE_REL_AMD64_REL32_1,
    IMAGE_REL_AMD64_REL32_2, IMAGE_REL_AMD64_REL32_3, IMAGE_REL_AMD64_REL32_4,
    IMAGE_REL_AMD64_REL32_5, IMAGE_REL_ARM64_ABSOLUTE, IMAGE_REL_ARM64_ADDR32,
    IMAGE_REL_ARM64_ADDR32NB, IMAGE_REL_ARM64_ADDR64, IMAGE_REL_ARM64_BRANCH14,
    IMAGE_REL_ARM64_BRANCH19, IMAGE_REL_ARM64_BRANCH26, IMAGE_REL_ARM64_PAGEBASE_REL21,
    IMAGE_REL_ARM64_PAGEOFFSET_12A, IMAGE_REL_ARM64_PAGEOFFSET_12L, IMAGE_REL_ARM64_REL21,
    IMAGE_REL_ARM64_REL32,
};

fn apply_one(
    target: &mut [u8],
    reloc_rva: u64,
    symbol_value: u64,
    is_absolute: bool,
    ty: u16,
    image_base: u64,
) {
    // COFF carries the addend in the instruction bytes at the relocation
    // site (e.g. a reference to `argc` at `.bss`+0x20 has disp 0x20 with a
    // relocation against the `.bss` section symbol). It must be included.
    match ty {
        IMAGE_REL_AMD64_ABSOLUTE => {}
        IMAGE_REL_AMD64_ADDR64 => {
            let addend = u64::from_le_bytes(target[..8].try_into().unwrap());
            // Absolute symbols (e.g. `__ImageBase`) already hold a VA.
            let v = if is_absolute {
                symbol_value.wrapping_add(addend)
            } else {
                symbol_value.wrapping_add(addend).wrapping_add(image_base)
            };
            target[..8].copy_from_slice(&v.to_le_bytes());
        }
        IMAGE_REL_AMD64_ADDR32 => {
            let addend = u32::from_le_bytes(target[..4].try_into().unwrap()) as u64;
            let v = if is_absolute {
                symbol_value.wrapping_add(addend) as u32
            } else {
                symbol_value.wrapping_add(addend).wrapping_add(image_base) as u32
            };
            target[..4].copy_from_slice(&v.to_le_bytes());
        }
        IMAGE_REL_AMD64_ADDR32NB => {
            let addend = u32::from_le_bytes(target[..4].try_into().unwrap()) as u64;
            let v = symbol_value.wrapping_add(addend) as u32;
            target[..4].copy_from_slice(&v.to_le_bytes());
        }
        IMAGE_REL_AMD64_REL32
        | IMAGE_REL_AMD64_REL32_1
        | IMAGE_REL_AMD64_REL32_2
        | IMAGE_REL_AMD64_REL32_3
        | IMAGE_REL_AMD64_REL32_4
        | IMAGE_REL_AMD64_REL32_5 => {
            let bias = (ty - IMAGE_REL_AMD64_REL32) as i64;
            let addend = i32::from_le_bytes(target[..4].try_into().unwrap()) as i64;
            let v = symbol_value as i64 + addend - reloc_rva as i64 - 4 - bias;
            if v < i32::MIN as i64 || v > i32::MAX as i64 {
                warn!("relocation overflow: value {v:#x} does not fit in 32 bits");
            }
            target[..4].copy_from_slice(&(v as i32).to_le_bytes());
        }
        _ => {}
    }
}

/// Sign-extend the low `bits` of `v`.
fn sext(v: u64, bits: u32) -> i64 {
    ((v << (64 - bits)) as i64) >> (64 - bits)
}

/// Applies one AArch64 relocation. Semantics follow LLD: the addend lives
/// in the instruction's immediate field; `S` is the symbol VA, `P` the
/// site VA.
fn apply_one_arm64(
    target: &mut [u8],
    reloc_rva: u64,
    symbol_value: u64,
    is_absolute: bool,
    ty: u16,
    image_base: u64,
) {
    let s = (if is_absolute { symbol_value } else { symbol_value.wrapping_add(image_base) }) as i64;
    let p = reloc_rva.wrapping_add(image_base) as i64;
    match ty {
        IMAGE_REL_ARM64_ABSOLUTE => {}
        IMAGE_REL_ARM64_ADDR32 => {
            let addend = u32::from_le_bytes(target[..4].try_into().unwrap()) as u64;
            let v = if is_absolute {
                symbol_value.wrapping_add(addend) as u32
            } else {
                symbol_value.wrapping_add(addend).wrapping_add(image_base) as u32
            };
            target[..4].copy_from_slice(&v.to_le_bytes());
        }
        IMAGE_REL_ARM64_ADDR32NB => {
            let addend = u32::from_le_bytes(target[..4].try_into().unwrap()) as u64;
            let v = symbol_value.wrapping_add(addend) as u32;
            target[..4].copy_from_slice(&v.to_le_bytes());
        }
        IMAGE_REL_ARM64_ADDR64 => {
            let addend = u64::from_le_bytes(target[..8].try_into().unwrap());
            let v = if is_absolute {
                symbol_value.wrapping_add(addend)
            } else {
                symbol_value.wrapping_add(addend).wrapping_add(image_base)
            };
            target[..8].copy_from_slice(&v.to_le_bytes());
        }
        IMAGE_REL_ARM64_REL32 => {
            let addend = i32::from_le_bytes(target[..4].try_into().unwrap()) as i64;
            let v = s + addend - p;
            if v < i32::MIN as i64 || v > i32::MAX as i64 {
                warn!("relocation overflow: value {v:#x} does not fit in 32 bits");
            }
            target[..4].copy_from_slice(&(v as i32).to_le_bytes());
        }
        IMAGE_REL_ARM64_BRANCH26 => {
            let insn = u32::from_le_bytes(target[..4].try_into().unwrap());
            let a = sext(((insn & 0x03FF_FFFF) as u64) << 2, 28);
            let t = s + a - p;
            if t & 3 != 0 || !(-(1 << 27)..(1 << 27)).contains(&t) {
                warn!("branch relocation out of range: {t:#x}");
            }
            let out = (insn & 0xFC00_0000) | (((t >> 2) as u32) & 0x03FF_FFFF);
            target[..4].copy_from_slice(&out.to_le_bytes());
        }
        IMAGE_REL_ARM64_BRANCH19 => {
            let insn = u32::from_le_bytes(target[..4].try_into().unwrap());
            let a = sext((((insn >> 5) & 0x7_FFFF) as u64) << 2, 21);
            let t = s + a - p;
            if t & 3 != 0 || !(-(1 << 20)..(1 << 20)).contains(&t) {
                warn!("branch relocation out of range: {t:#x}");
            }
            let out = (insn & 0xFF00_001F) | ((((t >> 2) as u32) & 0x7_FFFF) << 5);
            target[..4].copy_from_slice(&out.to_le_bytes());
        }
        IMAGE_REL_ARM64_BRANCH14 => {
            let insn = u32::from_le_bytes(target[..4].try_into().unwrap());
            let a = sext((((insn >> 5) & 0x3FFF) as u64) << 2, 16);
            let t = s + a - p;
            if t & 3 != 0 || !(-(1 << 15)..(1 << 15)).contains(&t) {
                warn!("branch relocation out of range: {t:#x}");
            }
            let out = (insn & 0xFF00_001F) | ((((t >> 2) as u32) & 0x3FFF) << 5);
            target[..4].copy_from_slice(&out.to_le_bytes());
        }
        IMAGE_REL_ARM64_PAGEBASE_REL21 | IMAGE_REL_ARM64_REL21 => {
            // ADRP (paged) and ADR (unpaged) share the immhi:immlo packing.
            let insn = u32::from_le_bytes(target[..4].try_into().unwrap());
            let hi = (insn >> 5) & 0x7_FFFF;
            let lo = (insn >> 29) & 0x3;
            let a = sext((((hi << 2) | lo) as u64) << 12, 33);
            let t = if ty == IMAGE_REL_ARM64_PAGEBASE_REL21 {
                ((s + a) & !0xFFF_i64) - (p & !0xFFF_i64)
            } else {
                s + a - p
            };
            if ty == IMAGE_REL_ARM64_PAGEBASE_REL21 {
                if !(-(1 << 32)..(1 << 32)).contains(&t) {
                    warn!("adrp relocation out of range: {t:#x}");
                }
            } else if !(-(1 << 20)..(1 << 20)).contains(&t) {
                warn!("adr relocation out of range: {t:#x}");
            }
            let enc = ((t >> 12) as u32) & 0x1F_FFFF;
            let out = (insn & 0x9F00_001F) | ((enc & 0x3) << 29) | (((enc >> 2) & 0x7_FFFF) << 5);
            target[..4].copy_from_slice(&out.to_le_bytes());
        }
        IMAGE_REL_ARM64_PAGEOFFSET_12A => {
            let insn = u32::from_le_bytes(target[..4].try_into().unwrap());
            let a = ((insn >> 10) & 0xFFF) as i64;
            let v = ((s + a) & 0xFFF) as u32;
            let out = (insn & 0xFFC0_03FF) | (v << 10);
            target[..4].copy_from_slice(&out.to_le_bytes());
        }
        IMAGE_REL_ARM64_PAGEOFFSET_12L => {
            let insn = u32::from_le_bytes(target[..4].try_into().unwrap());
            let scale = 1i64 << ((insn >> 30) & 3);
            // The field holds the byte offset divided by the access size.
            let a = (((insn >> 10) & 0xFFF) as i64) * scale;
            let tot = s + a;
            if tot & (scale - 1) != 0 {
                warn!("page-offset relocation misaligned: {tot:#x}");
            }
            let v = ((tot & 0xFFF) / scale) as u32;
            let out = (insn & 0xFFC0_03FF) | (v << 10);
            target[..4].copy_from_slice(&out.to_le_bytes());
        }
        _ => {}
    }
}

/// MinGW `.weak.` fallback: a weak-undefined reference to `X` resolves to
/// a defined `.weak.X` stub (e.g. crtbegin.o's
/// `.weak.__register_frame_info`, used when the DLL feature is absent)
/// when one was linked; otherwise the reference stays 0. This mirrors GNU
/// ld, which wires the weak reference to the local stub automatically.
fn weak_fallback(ctx: &Context, name: &[u8]) -> Option<u64> {
    let mut prefix = b".weak.".to_vec();
    prefix.extend_from_slice(name);
    if let Some(id) = ctx.find(&prefix) {
        if ctx.symbols[id].is_defined {
            return Some(ctx.symbols[id].resolved_value);
        }
    }
    // Suffixed variants (`.weak.X.<tag>`, e.g. `.hmod_libgcc`): pick the
    // first defined one in name order for determinism.
    let mut dot = prefix;
    dot.push(b'.');
    let mut candidates: Vec<&Vec<u8>> =
        ctx.symbol_map.keys().filter(|cand| cand.starts_with(&dot)).collect();
    candidates.sort();
    for cand in candidates {
        let id = ctx.symbol_map[cand];
        if ctx.symbols[id].is_defined {
            return Some(ctx.symbols[id].resolved_value);
        }
    }
    None
}

/// Builds the per-symbol global-id cache (see `Context::id_cache`).
/// Called once when the file/symbol sets are final.
pub fn build_id_cache(ctx: &mut Context) {
    let ctx_ref: &Context = ctx;
    ctx.id_cache = ctx_ref
        .files
        .par_iter()
        .map(|f| {
            f.all_syms
                .iter()
                .map(|raw| {
                    if raw.name.is_empty() {
                        None
                    } else {
                        ctx_ref.symbol_map.get(raw.name.as_slice()).copied()
                    }
                })
                .collect()
        })
        .collect();
}

/// Cached global id for a relocation's symbol: cache hit, else a live
/// lookup for names interned after the cache was built.
pub fn cached_id(ctx: &Context, file_id: usize, sym_idx: u32) -> Option<usize> {
    if let Some(hit) =
        ctx.id_cache.get(file_id).and_then(|v| v.get(sym_idx as usize)).copied().flatten()
    {
        return Some(hit);
    }
    let raw = ctx.files[file_id].all_syms.get(sym_idx as usize)?;
    if raw.name.is_empty() {
        return None;
    }
    ctx.find(&raw.name)
}

/// Resolves a relocation's symbol to an (RVA, is_absolute) pair.
fn resolve_symbol(ctx: &Context, file_id: usize, sym_idx: u32) -> (u64, bool, Option<usize>) {
    let obj = &ctx.files[file_id];
    let Some(raw) = obj.all_syms.get(sym_idx as usize) else {
        warn!("symbol index out of range: {sym_idx}");
        return (0, false, None);
    };
    // Defined global (or import thunk): look up the resolved address.
    if !raw.name.is_empty() {
        if let Some(id) = cached_id(ctx, file_id, sym_idx) {
            let sym = &ctx.symbols[id];
            if sym.is_defined {
                return (sym.resolved_value, sym.is_absolute, Some(id));
            }
            if sym.is_weak {
                if let Some(value) = weak_fallback(ctx, &raw.name) {
                    return (value, false, Some(id));
                }
                return (0, false, Some(id));
            }
            error!("undefined symbol in relocation: {}", String::from_utf8_lossy(&raw.name));
            return (0, false, Some(id));
        }
    }
    // Section symbol: section RVA + value. One exception: a reference
    // to a dead `.idata$4` / `.idata$5` section of an import member. GNU
    // ld discards those sections, synthesizes the import tables, and
    // redirects such references (the import thunks) to the IAT slot.
    if raw.section_idx > 0 && (raw.section_idx as usize) <= obj.sections.len() {
        let sec = &obj.sections[raw.section_idx as usize - 1];
        if !sec.is_alive
            && (sec.name == b".idata$4" || sec.name == b".idata$5")
            && crate::input_files::is_import_member(obj)
        {
            if let Some(thunk) = crate::input_files::thunk_symbols(obj).first() {
                let imp = [b"__imp_".as_slice(), thunk.as_slice()].concat();
                if let Some(id) = ctx.find(&imp) {
                    let sym = &ctx.symbols[id];
                    if sym.is_defined {
                        return (sym.resolved_value, false, Some(id));
                    }
                }
            }
            error!("undefined IAT slot in relocation: {}", String::from_utf8_lossy(&sec.name));
            return (0, false, None);
        }
        return (sec.rva + raw.value as u64, false, None);
    }
    // Absolute symbol used by raw index (not in the global table).
    if raw.section_idx == crate::pe::IMAGE_SYM_ABSOLUTE as i32 {
        return (raw.value as u64, true, None);
    }
    if !raw.name.is_empty() {
        error!("undefined symbol in relocation: {}", String::from_utf8_lossy(&raw.name));
    }
    (0, false, None)
}

/// Applies one input section's relocations into its output section's chunk
/// of the image. `chunk_base` is the chunk's absolute file offset; sites
/// outside the chunk are skipped so that parallel callers writing disjoint
/// chunks can never race, even on corrupt inputs (valid inputs never hit
/// the skip).
pub fn apply_section_relocations(ctx: &Context, r: SectionRef, image: &mut [u8], chunk_base: u64) {
    if ctx.files[r.0].sections[r.1].relocs.is_empty() {
        return;
    }
    let machine = ctx.files[r.0].machine;
    let is_arm64 = machine == crate::pe::COFF_MACHINE_ARM64;
    let (sec_rva, sec_file_off) = {
        let sec = &ctx.files[r.0].sections[r.1];
        (sec.rva, sec.file_offset)
    };
    let image_base = ctx.args.image_base;
    let n = ctx.files[r.0].sections[r.1].relocs.len();
    for i in 0..n {
        let reloc = ctx.files[r.0].sections[r.1].relocs[i];
        if reloc.ty == IMAGE_REL_AMD64_ABSOLUTE || reloc.ty == IMAGE_REL_ARM64_ABSOLUTE {
            continue;
        }
        let (symbol_value, is_absolute, _) = resolve_symbol(ctx, r.0, reloc.symbol_index);
        let reloc_rva = sec_rva + reloc.virtual_address as u64;
        let off = sec_file_off as usize + reloc.virtual_address as usize;
        let size = if reloc.ty == IMAGE_REL_AMD64_ADDR64 || reloc.ty == IMAGE_REL_ARM64_ADDR64 {
            8
        } else {
            4
        };
        let base = chunk_base as usize;
        if off < base || off + size > base + image.len() {
            warn!("relocation offset out of range");
            continue;
        }
        let off = off - base;
        if is_arm64 {
            apply_one_arm64(
                &mut image[off..off + size],
                reloc_rva,
                symbol_value,
                is_absolute,
                reloc.ty,
                image_base,
            );
        } else {
            apply_one(
                &mut image[off..off + size],
                reloc_rva,
                symbol_value,
                is_absolute,
                reloc.ty,
                image_base,
            );
        }
    }
}

pub fn apply_all_relocations(ctx: &Context, image: &mut [u8]) {
    let cells = mold_common::parallel::SyncUnsafeCell::from_mut(image);
    if cells.is_empty() {
        return;
    }
    // Sections in file-backed outputs go parallel (their file ranges are
    // disjoint); the rest (`.bss` has no file range, and zero-size sections
    // keep the exact sequential behavior) stay sequential, exactly as
    // before.
    let mut par: Vec<(SectionRef, u64)> = Vec::new();
    let mut seq: Vec<SectionRef> = Vec::new();
    for out in &ctx.output_sections {
        let backed = out.raw_data_size > 0;
        for &r in &out.inputs {
            let sec = &ctx.files[r.0].sections[r.1];
            if sec.relocs.is_empty() {
                continue;
            }
            if backed && sec.size > 0 {
                par.push((r, sec.file_offset));
            } else {
                seq.push(r);
            }
        }
    }
    // Ranges tile the outputs in order, so this list is already sorted;
    // verify disjointness (and image containment) linearly, falling back
    // to fully sequential if it ever fails to hold.
    let image_len = cells.len() as u64;
    let mut end = 0u64;
    let mut ok = true;
    for &(r, base) in &par {
        let len = ctx.files[r.0].sections[r.1].size;
        if base < end || base + len > image_len {
            ok = false;
            break;
        }
        end = base + len;
    }
    if !ok {
        let image = unsafe { mold_common::parallel::SyncUnsafeCell::as_mut_slice(cells) };
        for out in &ctx.output_sections {
            for &r in &out.inputs {
                if ctx.files[r.0].sections[r.1].relocs.is_empty() {
                    continue;
                }
                apply_section_relocations(ctx, r, image, 0);
            }
        }
        return;
    }
    par.par_iter().for_each(|&(r, base)| {
        let len = ctx.files[r.0].sections[r.1].size as usize;
        let Some(chunk) = cells.get(base as usize..base as usize + len) else {
            return;
        };
        // SAFETY: section file ranges are disjoint (checked above) and each
        // section's writes are confined to its range by the bounds check in
        // `apply_section_relocations`.
        let chunk = unsafe { mold_common::parallel::SyncUnsafeCell::as_mut_slice(chunk) };
        apply_section_relocations(ctx, r, chunk, base);
    });
    // Sequential tail (empty in valid links).
    if !seq.is_empty() {
        let image = unsafe { mold_common::parallel::SyncUnsafeCell::as_mut_slice(cells) };
        for &r in &seq {
            apply_section_relocations(ctx, r, image, 0);
        }
    }
}

/// Base-relocation types for `.reloc`.
pub const BASE_RELOC_HIGHLOW: u16 = 3;
pub const BASE_RELOC_DIR64: u16 = 10;

/// Collects the sites needing static base relocations (`.reloc`), mirroring
/// `apply_all_relocations`' decisions: absolute (`ADDR64`/`ADDR32`) sites
/// baked with the preferred image base. `RVA`/`REL32` sites need none.
/// Weak-undefined sites stay 0 and DLL-imported data covered by the runtime
/// pseudo-reloc list (which would double-apply a static delta) are skipped.
pub fn collect_base_relocs(ctx: &mut Context) {
    // Flat section list in layout order, processed in contiguous groups;
    // per-group page maps merge in order, and the per-page sort/dedupe
    // below erases any order effects, matching a sequential run exactly.
    let ctx_ref: &Context = ctx;
    let mut flat: Vec<SectionRef> = Vec::new();
    for out in &ctx_ref.output_sections {
        for &r in &out.inputs {
            if !ctx_ref.files[r.0].sections[r.1].relocs.is_empty() {
                flat.push(r);
            }
        }
    }
    let per_group: Vec<BTreeMap<u32, Vec<(u16, u16)>>> = flat
        .par_chunks(512)
        .map(|group| {
            let mut local: BTreeMap<u32, Vec<(u16, u16)>> = BTreeMap::new();
            for &r in group {
                // Relocation type numbers overlap between architectures
                // (e.g. 1 is `ADDR64` on AMD64 but `ADDR32` on ARM64).
                let is_arm64 = ctx_ref.files[r.0].machine == crate::pe::COFF_MACHINE_ARM64;
                let sec_rva = ctx_ref.files[r.0].sections[r.1].rva;
                let n = ctx_ref.files[r.0].sections[r.1].relocs.len();
                for i in 0..n {
                    let reloc = ctx_ref.files[r.0].sections[r.1].relocs[i];
                    let rtype = if is_arm64 {
                        match reloc.ty {
                            IMAGE_REL_ARM64_ADDR64 => BASE_RELOC_DIR64,
                            IMAGE_REL_ARM64_ADDR32 => BASE_RELOC_HIGHLOW,
                            _ => continue,
                        }
                    } else {
                        match reloc.ty {
                            IMAGE_REL_AMD64_ADDR64 => BASE_RELOC_DIR64,
                            IMAGE_REL_AMD64_ADDR32 => BASE_RELOC_HIGHLOW,
                            _ => continue,
                        }
                    };
                    let (_, is_absolute, global) = resolve_symbol(ctx_ref, r.0, reloc.symbol_index);
                    if is_absolute {
                        continue;
                    }
                    // Weak-undefined references resolve to 0; no fixup needed.
                    // DLL-imported data with a runtime pseudo-reloc item is
                    // fixed at startup; a static entry would double-apply.
                    if let Some(id) = global {
                        let sym = &ctx_ref.symbols[id];
                        if sym.is_weak && !sym.is_defined {
                            continue;
                        }
                        let is_addr64 = if is_arm64 {
                            reloc.ty == IMAGE_REL_ARM64_ADDR64
                        } else {
                            reloc.ty == IMAGE_REL_AMD64_ADDR64
                        };
                        if is_addr64
                            && sym.is_dll_import
                            && sym.section.is_none()
                            && !sym.name.starts_with(b"__imp_")
                            && sym.resolved_value != 0
                        {
                            continue;
                        }
                    }
                    let rva = sec_rva + reloc.virtual_address as u64;
                    let page = (rva & !0xFFF) as u32;
                    let off = (rva & 0xFFF) as u16;
                    local.entry(page).or_default().push((rtype, off));
                }
            }
            local
        })
        .collect();
    ctx.base_reloc_pages.clear();
    for local in per_group {
        for (page, entries) in local {
            ctx.base_reloc_pages.entry(page).or_default().extend(entries);
        }
    }
    // Sort and dedupe each page for deterministic blocks.
    for entries in ctx.base_reloc_pages.values_mut() {
        entries.sort();
        entries.dedup();
    }
}

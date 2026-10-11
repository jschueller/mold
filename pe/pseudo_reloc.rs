//! MinGW runtime pseudo-relocations for auto-imported data.
//!
//! When code takes the address of DLL-imported data (e.g. `std::cout`),
//! the compiler emits a `.refptr` slot holding the IAT slot's address and
//! references the slot. The true data address only exists at load time, so
//! GNU ld emits a `__RUNTIME_PSEUDO_RELOC_LIST__` that MinGW startup
//! (`_pei386_runtime_relocator`, always linked via `crt2.o`) applies before
//! `main` runs. Without it the program observes the IAT slot's address
//! instead of the object and crashes inside the DLL.
//!
//! Format (v2, reverse-engineered from `libmingw32.a`'s relocator and GNU
//! ld output): a 12-byte header `{0, 0, 1}` followed by 12-byte items
//! `{iat_rva, slot_rva, 0x40}`. The relocator computes
//! `*slot = *slot_old - (base + iat_rva) + *iat`; since the slot
//! statically holds `base + iat_rva`, the result is `*iat`, the DLL data
//! address. List bounds come from `__RUNTIME_PSEUDO_RELOC_LIST__` /
//! `__RUNTIME_PSEUDO_RELOC_LIST_END__`, which MinGW's
//! `pseudo-reloc-list.o` also defines as commons (empty list) when we emit
//! nothing.

use rayon::prelude::*;

use crate::context::{Context, SectionRef};
use crate::pe::{IMAGE_REL_AMD64_ADDR64, IMAGE_REL_ARM64_ADDR64};

pub const LIST_START: &[u8] = b"__RUNTIME_PSEUDO_RELOC_LIST__";
pub const LIST_END: &[u8] = b"__RUNTIME_PSEUDO_RELOC_LIST_END__";

/// 64-bit patch flag, matching what GNU ld writes for `ADDR64` slots.
pub const ITEM_FLAGS: u32 = 0x40;

/// Size of the list blob (header + items), or 0 when there is nothing to
/// emit. The layout pass reserves this in `.rdata`.
pub fn blob_size(ctx: &Context) -> u64 {
    if !ctx.args.enable_runtime_pseudo_reloc || ctx.pseudo_reloc_items.is_empty() {
        0
    } else {
        12 + 12 * ctx.pseudo_reloc_items.len() as u64
    }
}

/// Collect `(slot_rva, iat_rva)` items and define the list symbols.
///
/// Any `ADDR64` relocation (typically in a merged `.refptr` slot, but also
/// direct data-pointer initializers) resolving to DLL-imported data needs
/// its location patched at startup. Function imports resolve to `.text`
/// thunks (a final address) and `__imp_` references must keep pointing at
/// the IAT, so both are skipped.
pub fn build(ctx: &mut Context) {
    ctx.pseudo_reloc_items.clear();
    if !ctx.args.enable_runtime_pseudo_reloc {
        return;
    }
    // Flat section list in layout order, processed in contiguous groups and
    // concatenated in order; the sort/dedupe below erases any order
    // effects, matching a sequential run exactly.
    let ctx_ref: &Context = ctx;
    let mut flat: Vec<SectionRef> = Vec::new();
    for out in &ctx_ref.output_sections {
        for &r in &out.inputs {
            if !ctx_ref.files[r.0].sections[r.1].relocs.is_empty() {
                flat.push(r);
            }
        }
    }
    let per_group: Vec<Vec<(u64, u64)>> = flat
        .par_chunks(512)
        .map(|group| {
            let mut items = Vec::new();
            for &r in group {
                if !ctx_ref.files[r.0].sections[r.1].is_alive
                    || ctx_ref.files[r.0].sections[r.1].relocs.is_empty()
                {
                    continue;
                }
                let sec_rva = ctx_ref.files[r.0].sections[r.1].rva;
                let is_arm64 = ctx_ref.files[r.0].machine == crate::pe::COFF_MACHINE_ARM64;
                let n = ctx_ref.files[r.0].sections[r.1].relocs.len();
                for i in 0..n {
                    let reloc = ctx_ref.files[r.0].sections[r.1].relocs[i];
                    // Type numbers overlap between architectures.
                    let is_addr64 = if is_arm64 {
                        reloc.ty == IMAGE_REL_ARM64_ADDR64
                    } else {
                        reloc.ty == IMAGE_REL_AMD64_ADDR64
                    };
                    if !is_addr64 {
                        continue;
                    }
                    let Some(raw) = ctx_ref.files[r.0].all_syms.get(reloc.symbol_index as usize)
                    else {
                        continue;
                    };
                    if raw.name.is_empty() {
                        continue;
                    }
                    let Some(id) = crate::relocations::cached_id(ctx_ref, r.0, reloc.symbol_index)
                    else {
                        continue;
                    };
                    let sym = &ctx_ref.symbols[id];
                    if !sym.is_dll_import || sym.section.is_some() {
                        continue;
                    }
                    if sym.name.starts_with(b"__imp_") {
                        continue;
                    }
                    if sym.resolved_value == 0 {
                        continue;
                    }
                    items.push((sec_rva + reloc.virtual_address as u64, sym.resolved_value));
                }
            }
            items
        })
        .collect();
    let mut items: Vec<(u64, u64)> = per_group.into_iter().flatten().collect();
    items.sort();
    items.dedup();
    ctx.pseudo_reloc_items = items;
    if ctx.pseudo_reloc_items.is_empty() {
        return;
    }
    // The layout pass assigns `pseudo_reloc_rva`; on the first iteration
    // it has not reserved the blob yet, so symbols are defined on the
    // re-run (item count, hence blob size, is layout-independent).
    let base = ctx.pseudo_reloc_rva;
    if base == 0 {
        return;
    }
    let end = base + blob_size(ctx);
    for (name, value) in [(LIST_START, base), (LIST_END, end)] {
        let id = ctx.get_or_intern(name);
        let sym = &mut ctx.symbols[id];
        sym.is_defined = true;
        sym.is_undefined = false;
        sym.section = None;
        sym.value = 0;
        sym.resolved_value = value;
    }
}

//! Final image assembly: section contents, import/export tables.
//!
//! Ported from `src/pe-coff/writer.cc`.

use mold_common::mapped_file::apply_chroot;
use mold_common::output_file::OutputFile;

use crate::context::Context;
use crate::output::{file_size, write_headers};

pub fn import_descriptor_size(ctx: &Context) -> u64 {
    (ctx.import_dlls.len() + 1) as u64 * 20
}

pub fn import_ilt_size(ctx: &Context) -> u64 {
    ctx.import_dlls.iter().map(|d| (d.entries.len() + 1) as u64 * 8).sum()
}

fn import_name_table_size(ctx: &Context) -> u64 {
    let mut size = 0u64;
    for dll in &ctx.import_dlls {
        for &id in &dll.entries {
            size += 2 + ctx.symbols[id].import_name.len() as u64 + 1;
            if size & 1 == 1 {
                size += 1;
            }
        }
    }
    size
}

fn import_dll_name_size(ctx: &Context) -> u64 {
    ctx.import_dlls.iter().map(|d| d.dll_name.len() as u64 + 1).sum()
}

pub fn import_total_size(ctx: &Context) -> u32 {
    // The ILT/IAT hold 8-byte slots and must start 8-aligned (AArch64
    // faults on misaligned loads); descriptors are 20 bytes each.
    let desc = import_descriptor_size(ctx);
    let ilt_pad = (8 - desc % 8) % 8;
    (desc + ilt_pad + import_ilt_size(ctx) * 2 + import_name_table_size(ctx) + import_dll_name_size(ctx))
        as u32
}

/// RVAs of the four import-table regions for a `.idata` at `base_rva`:
/// the ILT, IAT, hint/name table and DLL names. The single source of
/// truth for the layout; the table writer and the IAT-slot address
/// assignment must agree exactly.
pub fn import_table_rvas(ctx: &Context, base_rva: u64) -> (u64, u64, u64, u64) {
    let ilt_start = import_descriptor_size(ctx).next_multiple_of(8);
    let ilt_size = import_ilt_size(ctx);
    let ilt_rva = base_rva + ilt_start;
    let iat_rva = ilt_rva + ilt_size;
    let name_rva = iat_rva + ilt_size;
    let dll_rva = name_rva + import_name_table_size(ctx);
    (ilt_rva, iat_rva, name_rva, dll_rva)
}

pub fn export_total_size(ctx: &Context) -> u32 {
    if ctx.export_names.is_empty() {
        return 0;
    }
    let n = ctx.export_names.len() as u32;
    // directory + EAT + name pointers + ordinals + strings (dll name + names).
    let mut strings = ctx.export_dll_name.len() as u32 + 1;
    for (name, _) in &ctx.export_names {
        strings += name.len() as u32 + 1;
    }
    40 + n * 4 + n * 4 + n * 2 + strings
}

fn write_import_table(ctx: &Context, buf: &mut [u8], base_rva: u64) {
    let (ilt_rva, iat_rva, name_rva, dll_rva) = import_table_rvas(ctx, base_rva);
    // File offsets mirror the RVAs (the section starts at base_rva).
    let off = |rva: u64| (rva - base_rva) as usize;
    let (mut ilt_off, mut iat_off, mut name_off, mut dll_off) =
        (off(ilt_rva), off(iat_rva), off(name_rva), off(dll_rva));
    let mut desc_off = 0usize;
    let mut cur_name_rva = name_rva;
    let mut cur_dll_rva = dll_rva;
    let mut cur_ilt_rva = ilt_rva;
    let mut cur_iat_rva = iat_rva;

    for dll in &ctx.import_dlls {
        buf[desc_off..desc_off + 4].copy_from_slice(&(cur_ilt_rva as u32).to_le_bytes());
        buf[desc_off + 12..desc_off + 16].copy_from_slice(&(cur_dll_rva as u32).to_le_bytes());
        buf[desc_off + 16..desc_off + 20].copy_from_slice(&(cur_iat_rva as u32).to_le_bytes());
        desc_off += 20;

        buf[dll_off..dll_off + dll.dll_name.len()].copy_from_slice(&dll.dll_name);
        dll_off += dll.dll_name.len() + 1;
        cur_dll_rva += dll.dll_name.len() as u64 + 1;

        for &id in &dll.entries {
            buf[ilt_off..ilt_off + 8].copy_from_slice(&(cur_name_rva as u64).to_le_bytes());
            buf[iat_off..iat_off + 8].copy_from_slice(&(cur_name_rva as u64).to_le_bytes());
            ilt_off += 8;
            iat_off += 8;

            let sym = &ctx.symbols[id];
            buf[name_off..name_off + 2].copy_from_slice(&sym.ordinal_hint.to_le_bytes());
            name_off += 2;
            buf[name_off..name_off + sym.import_name.len()].copy_from_slice(&sym.import_name);
            name_off += sym.import_name.len() + 1;
            let mut entry_len = 2 + sym.import_name.len() as u64 + 1;
            if entry_len & 1 == 1 {
                name_off += 1;
                entry_len += 1;
            }
            cur_name_rva += entry_len;
        }
        ilt_off += 8;
        iat_off += 8;
        cur_ilt_rva += (dll.entries.len() + 1) as u64 * 8;
        cur_iat_rva += (dll.entries.len() + 1) as u64 * 8;
    }
}

fn write_export_table(ctx: &Context, buf: &mut [u8], base_rva: u64) {
    let n = ctx.export_names.len();
    buf[16..20]
        .copy_from_slice(&(base_rva as u32 + ctx.export_dll_name.len() as u32 + 1).to_le_bytes());
    // Simpler: Name = strings start (dll name first).
    let dir_size = 40usize;
    let eat_size = n * 4;
    let name_ptr_size = n * 4;
    let ord_size = n * 2;
    let strings_off = dir_size + eat_size + name_ptr_size + ord_size;

    buf[0..4].copy_from_slice(&0u32.to_le_bytes());
    buf[4..8].copy_from_slice(&0u32.to_le_bytes());
    buf[12..16].copy_from_slice(&(base_rva as u32 + strings_off as u32).to_le_bytes());
    buf[16..20].copy_from_slice(&1u32.to_le_bytes());
    buf[20..24].copy_from_slice(&(n as u32).to_le_bytes());
    buf[24..28].copy_from_slice(&(n as u32).to_le_bytes());
    buf[28..32].copy_from_slice(&(base_rva as u32 + dir_size as u32).to_le_bytes());
    buf[32..36].copy_from_slice(&(base_rva as u32 + (dir_size + eat_size) as u32).to_le_bytes());
    buf[36..40].copy_from_slice(
        &(base_rva as u32 + (dir_size + eat_size + name_ptr_size) as u32).to_le_bytes(),
    );

    // EAT: RVAs of exported symbols.
    for (i, (_, id)) in ctx.export_names.iter().enumerate() {
        let rva = ctx.symbols[*id].resolved_value as u32;
        buf[dir_size + i * 4..dir_size + i * 4 + 4].copy_from_slice(&rva.to_le_bytes());
    }
    // Name pointers + ordinals.
    let mut cur = base_rva + strings_off as u64 + ctx.export_dll_name.len() as u64 + 1;
    for (i, (name, _)) in ctx.export_names.iter().enumerate() {
        buf[dir_size + eat_size + i * 4..dir_size + eat_size + i * 4 + 4]
            .copy_from_slice(&(cur as u32).to_le_bytes());
        buf[dir_size + eat_size + name_ptr_size + i * 2
            ..dir_size + eat_size + name_ptr_size + i * 2 + 2]
            .copy_from_slice(&(i as u16).to_le_bytes());
        cur += name.len() as u64 + 1;
    }
    // Strings: dll name, then export names.
    let mut o = strings_off;
    buf[o..o + ctx.export_dll_name.len()].copy_from_slice(&ctx.export_dll_name);
    o += ctx.export_dll_name.len() + 1;
    for (name, _) in &ctx.export_names {
        buf[o..o + name.len()].copy_from_slice(name);
        o += name.len() + 1;
    }
}

pub fn write_output(ctx: &mut Context) {
    let size = file_size(ctx);
    let path = apply_chroot(&ctx.args.chroot, &ctx.args.output).into_owned();
    let mut output = OutputFile::open(&path, size, 0o755, false, ctx.args.mmap_output_file);
    let buf = output.buf();
    buf.fill(0);

    write_headers(ctx, buf);

    // Section contents.
    for out in &ctx.output_sections {
        if out.raw_data_size == 0 {
            continue;
        }
        let base = out.file_offset as usize;
        for &r in &out.inputs {
            let sec = &ctx.files[r.0].sections[r.1];
            if !sec.is_alive || sec.contents.is_empty() {
                continue;
            }
            let off = base + (sec.rva - out.rva) as usize;
            buf[off..off + sec.contents.len()].copy_from_slice(sec.contents);
        }
    }

    // Relocations after contents are in place.
    crate::relocations::apply_all_relocations(ctx, buf);

    // `.ctors`/`.dtors` `-1` sentinel heads (tails are zero padding).
    let mut heads = Vec::new();
    for (out_id, out) in ctx.output_sections.iter().enumerate() {
        if out.name == b".ctors" || out.name == b".dtors" {
            if crate::passes::ctor_head_size(ctx, out_id) == 8 {
                heads.push(out.file_offset as usize);
            }
        }
    }
    for off in heads {
        buf[off..off + 8].copy_from_slice(&(-1i64).to_le_bytes());
    }

    // Synthetic tables overwrite their sections.
    if let Some(id) = ctx.idata_section {
        if !ctx.import_dlls.is_empty() {
            let (off, rva, _size) = {
                let s = &ctx.output_sections[id];
                (s.file_offset as usize, s.rva, s.raw_data_size as usize)
            };
            let total = import_total_size(ctx) as usize;
            buf[off..off + total].fill(0);
            write_import_table(ctx, &mut buf[off..off + total], rva);
        }
    }
    if let Some(id) = ctx.edata_section {
        if !ctx.export_names.is_empty() {
            let (off, rva) = {
                let s = &ctx.output_sections[id];
                (s.file_offset as usize, s.rva)
            };
            let total = export_total_size(ctx) as usize;
            buf[off..off + total].fill(0);
            write_export_table(ctx, &mut buf[off..off + total], rva);
        }
    }
    write_pseudo_reloc_list(ctx, buf);

    // Base relocations: the blocks were sized during layout.
    if let Some(id) = ctx.reloc_section {
        if !ctx.base_reloc_blocks.is_empty() {
            let off = ctx.output_sections[id].file_offset as usize;
            let total = ctx.base_reloc_blocks.len();
            buf[off..off + total].copy_from_slice(&ctx.base_reloc_blocks);
        }
    }

    mold_common::error::checkpoint();
    output.close();
}

/// Write the `__RUNTIME_PSEUDO_RELOC_LIST__` blob (v2: header `{0, 0, 1}`
/// plus `{iat_rva, slot_rva, 0x40}` items) at the end of `.rdata`.
fn write_pseudo_reloc_list(ctx: &Context, buf: &mut [u8]) {
    if ctx.pseudo_reloc_items.is_empty() || ctx.pseudo_reloc_rva == 0 {
        return;
    }
    let Some(id) = ctx.rdata_section else {
        return;
    };
    let (off, rva) = {
        let s = &ctx.output_sections[id];
        (s.file_offset as usize, s.rva)
    };
    let mut items = ctx.pseudo_reloc_items.clone();
    items.sort();
    let mut p = off + (ctx.pseudo_reloc_rva - rva) as usize;
    for v in [0u32, 0, 1] {
        buf[p..p + 4].copy_from_slice(&v.to_le_bytes());
        p += 4;
    }
    for (slot, iat) in &items {
        for v in [*iat as u32, *slot as u32, crate::pseudo_reloc::ITEM_FLAGS] {
            buf[p..p + 4].copy_from_slice(&v.to_le_bytes());
            p += 4;
        }
    }
}

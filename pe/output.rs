//! Image layout and PE header emission.
//!
//! Ported from `src/pe-coff/output.cc`.

use crate::context::Context;
use crate::pe::{
    self, FILE_ALIGNMENT, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, IMAGE_DLLCHARACTERISTICS_NX_COMPAT, IMAGE_FILE_DLL,
    IMAGE_FILE_EXECUTABLE_IMAGE, IMAGE_FILE_LARGE_ADDRESS_AWARE, IMAGE_SCN_CNT_CODE,
    IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA, PE32_PLUS_MAGIC,
    SECTION_ALIGNMENT,
};
use crate::writer::{export_total_size, import_total_size};

pub fn compute_output_size(ctx: &mut Context, out_id: usize) {
    // The synthetic `.reloc` section keeps the size assigned by
    // `size_reloc_section`; it has no inputs to measure.
    if Some(out_id) == ctx.reloc_section && !ctx.base_reloc_blocks.is_empty() {
        return;
    }
    // `.ctors`/`.dtors` outputs are framed with a `-1` sentinel head and
    // a `0` terminator tail (see `passes::ctor_head_size`).
    let head = crate::passes::ctor_head_size(ctx, out_id);
    let is_ctor = {
        let name = &ctx.output_sections[out_id].name;
        name == b".ctors" || name == b".dtors"
    };
    let n_inputs = ctx.output_sections[out_id].inputs.len();
    let mut offset = head;
    for ii in 0..n_inputs {
        let r = ctx.output_sections[out_id].inputs[ii];
        let sec = &mut ctx.files[r.0].sections[r.1];
        if !sec.is_alive {
            continue;
        }
        let mut align = pe::section_alignment(sec.characteristics);
        if align < 4 {
            align = 4;
        }
        let out_rva = ctx.output_sections[out_id].rva;
        let out_off = ctx.output_sections[out_id].file_offset;
        // The output's own alignment is the max of its inputs.
        if align > ctx.output_sections[out_id].alignment {
            ctx.output_sections[out_id].alignment = align;
        }
        offset = align_up(offset, align);
        sec.rva = out_rva + offset;
        sec.file_offset = out_off + offset;
        offset += sec.size;
    }
    // The `0` terminator tail lives in the zero padding (the image buffer
    // starts zero-filled); only the size must account for it.
    let tail = u64::from(is_ctor) * 8;
    let out = &mut ctx.output_sections[out_id];
    out.virtual_size = offset + tail;
    out.raw_data_size = offset + tail;
    if out.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
        out.raw_data_size = 0;
    }
}

fn align_up(v: u64, align: u64) -> u64 {
    (v + align - 1) & !(align - 1)
}

/// Reserve room for the runtime pseudo-reloc list at the end of `.rdata`
/// and record its RVA. Called from both layout passes; the item count (and
/// hence the size) is layout-independent, so the second pass is stable.
fn reserve_pseudo_reloc_blob(ctx: &mut Context, out_id: usize) {
    if Some(out_id) != ctx.rdata_section {
        return;
    }
    let size = crate::pseudo_reloc::blob_size(ctx);
    if size == 0 {
        ctx.pseudo_reloc_rva = 0;
        return;
    }
    let off = align_up(ctx.output_sections[out_id].virtual_size, 4);
    ctx.pseudo_reloc_rva = ctx.output_sections[out_id].rva + off;
    let need = off + size;
    let out = &mut ctx.output_sections[out_id];
    if need > out.virtual_size {
        out.virtual_size = need;
        out.raw_data_size = need;
    }
}

pub fn calculate_layout(ctx: &mut Context) {
    // First pass: input-driven sizes.
    for out_id in 0..ctx.output_sections.len() {
        // Temporarily zero RVAs; real assignment happens below.
        ctx.output_sections[out_id].rva = 0;
        ctx.output_sections[out_id].file_offset = 0;
        compute_output_size(ctx, out_id);
        // Synthetic sections grow to fit their tables.
        let extra = if Some(out_id) == ctx.idata_section {
            import_total_size(ctx) as u64
        } else if Some(out_id) == ctx.edata_section {
            export_total_size(ctx) as u64
        } else {
            0
        };
        if extra > ctx.output_sections[out_id].virtual_size {
            ctx.output_sections[out_id].virtual_size = extra;
            ctx.output_sections[out_id].raw_data_size = extra;
        }
        reserve_pseudo_reloc_blob(ctx, out_id);
    }

    let num_sections =
        ctx.output_sections.iter().filter(|s| s.virtual_size > 0 || s.raw_data_size > 0).count();

    // DOS stub (64) + PE sig (4) + COFF header (20) + optional header + section headers.
    let mut headers_size = 64 + 4 + 20 + optional_header_size() + num_sections as u64 * 40;
    headers_size = align_up(headers_size, FILE_ALIGNMENT);

    let mut rva = SECTION_ALIGNMENT;
    let mut file_offset = headers_size;
    for out_id in 0..ctx.output_sections.len() {
        if ctx.output_sections[out_id].virtual_size == 0
            && ctx.output_sections[out_id].raw_data_size == 0
        {
            continue;
        }
        let align = ctx.output_sections[out_id].alignment.max(SECTION_ALIGNMENT);
        rva = align_up(rva, align);
        file_offset = align_up(file_offset, FILE_ALIGNMENT);
        ctx.output_sections[out_id].rva = rva;
        ctx.output_sections[out_id].file_offset = file_offset;
        compute_output_size(ctx, out_id);
        let extra = if Some(out_id) == ctx.idata_section {
            import_total_size(ctx) as u64
        } else if Some(out_id) == ctx.edata_section {
            export_total_size(ctx) as u64
        } else {
            0
        };
        if extra > ctx.output_sections[out_id].virtual_size {
            ctx.output_sections[out_id].virtual_size = extra;
            ctx.output_sections[out_id].raw_data_size = extra;
        }
        reserve_pseudo_reloc_blob(ctx, out_id);
        let data_size = ctx.output_sections[out_id].raw_data_size;
        rva += ctx.output_sections[out_id].virtual_size.max(1);
        // Keep RVAs page-aligned per section like the prototype does by
        // rounding the running RVA up on the next iteration.
        file_offset += data_size;
    }

    ctx.headers_size = headers_size;
    ctx.image_size = align_up(rva, SECTION_ALIGNMENT);
}

/// Serializes `base_reloc_pages` into `.reloc` blocks and assigns the
/// section size. Returns true when the size changed (drives layout
/// fixpoint iteration in `run_linking_passes`).
pub fn size_reloc_section(ctx: &mut Context) -> bool {
    let mut blocks = Vec::new();
    for (&page, entries) in &ctx.base_reloc_pages {
        if entries.is_empty() {
            continue;
        }
        let mut block = Vec::with_capacity(8 + entries.len() * 2);
        block.extend_from_slice(&page.to_le_bytes());
        block.extend_from_slice(&0u32.to_le_bytes()); // size placeholder
        for &(ty, off) in entries {
            block.extend_from_slice(&(ty << 12 | (off & 0xFFF)).to_le_bytes());
        }
        while block.len() & 3 != 0 {
            block.extend_from_slice(&0u16.to_le_bytes());
        }
        let size = block.len() as u32;
        block[4..8].copy_from_slice(&size.to_le_bytes());
        blocks.extend_from_slice(&block);
    }
    let changed = ctx.base_reloc_blocks != blocks;
    let size = blocks.len() as u64;
    ctx.base_reloc_blocks = blocks;
    if let Some(id) = ctx.reloc_section {
        ctx.output_sections[id].virtual_size = size;
        ctx.output_sections[id].raw_data_size = size;
    }
    changed
}

pub fn optional_header_size() -> u64 {
    // PeOptionalHeader64 as written by write_optional_header: fixed fields
    // (112 bytes) + 16 data-directory entries (8 bytes each) = 240.
    240
}

pub fn file_size(ctx: &Context) -> u64 {
    let mut size = ctx.headers_size;
    for sec in &ctx.output_sections {
        if sec.raw_data_size > 0 {
            size = size.max(sec.file_offset + sec.raw_data_size);
        }
    }
    size
}

pub fn write_headers(ctx: &Context, buf: &mut [u8]) {
    write_dos_stub(&mut buf[..64]);
    buf[64..68].copy_from_slice(b"PE\0\0");

    // COFF header.
    let coff = &mut buf[68..88];
    let num_sections =
        ctx.output_sections.iter().filter(|s| s.virtual_size > 0 || s.raw_data_size > 0).count()
            as u16;
    let machine = if ctx.target_machine != 0 { ctx.target_machine } else { pe::COFF_MACHINE_AMD64 };
    coff[0..2].copy_from_slice(&machine.to_le_bytes());
    coff[2..4].copy_from_slice(&num_sections.to_le_bytes());
    coff[4..8].copy_from_slice(&0u32.to_le_bytes());
    coff[8..12].copy_from_slice(&0u32.to_le_bytes());
    coff[12..16].copy_from_slice(&0u32.to_le_bytes());
    coff[16..18].copy_from_slice(&(optional_header_size() as u16).to_le_bytes());
    let mut chars = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;
    if ctx.args.is_dll {
        chars |= IMAGE_FILE_DLL;
    }
    coff[18..20].copy_from_slice(&chars.to_le_bytes());

    write_optional_header(ctx, &mut buf[88..88 + optional_header_size() as usize]);

    // Section headers.
    let mut off = 88 + optional_header_size() as usize;
    for sec in &ctx.output_sections {
        if sec.virtual_size == 0 && sec.raw_data_size == 0 {
            continue;
        }
        let h = &mut buf[off..off + 40];
        h.fill(0);
        let name_len = sec.name.len().min(8);
        h[..name_len].copy_from_slice(&sec.name[..name_len]);
        h[8..12].copy_from_slice(&(sec.virtual_size as u32).to_le_bytes());
        h[12..16].copy_from_slice(&(sec.rva as u32).to_le_bytes());
        h[16..20].copy_from_slice(&(sec.raw_data_size as u32).to_le_bytes());
        // Sections without file contents (e.g. `.bss`) must not point
        // into the file; the loader rejects a nonzero pointer here.
        let raw_ptr = if sec.raw_data_size == 0 { 0 } else { sec.file_offset as u32 };
        h[20..24].copy_from_slice(&raw_ptr.to_le_bytes());
        h[36..40].copy_from_slice(&sec.characteristics.to_le_bytes());
        off += 40;
    }
}

fn write_dos_stub(buf: &mut [u8]) {
    buf.fill(0);
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[2] = 0x90;
    buf[4] = 0x03;
    buf[8] = 0x04;
    buf[12] = 0xFF;
    buf[13] = 0xFF;
    buf[16] = 0xB8;
    buf[60] = 64;
}

fn write_optional_header(ctx: &Context, buf: &mut [u8]) {
    buf.fill(0);
    buf[0..2].copy_from_slice(&PE32_PLUS_MAGIC.to_le_bytes());
    buf[2] = 1; // MajorLinkerVersion

    let mut size_code = 0u32;
    let mut size_init = 0u32;
    let mut size_uninit = 0u32;
    for sec in &ctx.output_sections {
        if sec.characteristics & IMAGE_SCN_CNT_CODE != 0 {
            size_code += sec.raw_data_size as u32;
        }
        if sec.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0
            && sec.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA == 0
        {
            size_init += sec.raw_data_size as u32;
        }
        if sec.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
            size_uninit += sec.virtual_size as u32;
        }
    }
    buf[4..8].copy_from_slice(&size_code.to_le_bytes());
    buf[8..12].copy_from_slice(&size_init.to_le_bytes());
    buf[12..16].copy_from_slice(&size_uninit.to_le_bytes());
    buf[16..20].copy_from_slice(&(ctx.entry_point_rva as u32).to_le_bytes());
    // BaseOfCode left 0.
    buf[24..32].copy_from_slice(&ctx.args.image_base.to_le_bytes());
    buf[32..36].copy_from_slice(&(SECTION_ALIGNMENT as u32).to_le_bytes());
    buf[36..40].copy_from_slice(&(FILE_ALIGNMENT as u32).to_le_bytes());
    buf[40..42].copy_from_slice(&6u16.to_le_bytes()); // OS version 6.0
    buf[48..50].copy_from_slice(&6u16.to_le_bytes()); // Subsystem version 6.0
    buf[56..60].copy_from_slice(&(ctx.image_size as u32).to_le_bytes());
    buf[60..64].copy_from_slice(&(ctx.headers_size as u32).to_le_bytes());
    // CheckSum left 0.
    buf[68..70].copy_from_slice(&ctx.args.subsystem.to_le_bytes());
    let mut dll_chars =
        IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
    if ctx.args.dynamic_base {
        dll_chars |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
    }
    buf[70..72].copy_from_slice(&dll_chars.to_le_bytes());
    buf[72..80].copy_from_slice(&0x40_0000u64.to_le_bytes()); // StackReserve
    buf[80..88].copy_from_slice(&0x1000u64.to_le_bytes()); // StackCommit
    buf[88..96].copy_from_slice(&0x10_0000u64.to_le_bytes()); // HeapReserve
    buf[96..104].copy_from_slice(&0x1000u64.to_le_bytes()); // HeapCommit
    buf[108..112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

    // Data directories: [rva, size] pairs starting at offset 112.
    let mut dir = |idx: usize, rva: u32, size: u32| {
        let o = 112 + idx * 8;
        buf[o..o + 4].copy_from_slice(&rva.to_le_bytes());
        buf[o + 4..o + 8].copy_from_slice(&size.to_le_bytes());
    };
    if let Some(id) = ctx.edata_section {
        if !ctx.export_names.is_empty() {
            dir(0, ctx.output_sections[id].rva as u32, export_total_size(ctx));
        }
    }
    if let Some(id) = ctx.idata_section {
        if !ctx.import_dlls.is_empty() {
            dir(
                1,
                ctx.output_sections[id].rva as u32,
                crate::writer::import_descriptor_size(ctx) as u32,
            );
        }
    }
    if let Some(id) = ctx.reloc_section {
        if !ctx.base_reloc_blocks.is_empty() {
            let s = &ctx.output_sections[id];
            dir(5, s.rva as u32, s.raw_data_size as u32);
        }
    }
}

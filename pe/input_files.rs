//! COFF object, archive and import-library parsing.
//!
//! Ported from `src/pe-coff/input-files.cc`. Archive handling supports the
//! SysV layout that MinGW's `ar` writes: linker members named `/` (with a
//! big-endian symbol index), a `//` long-name member, then regular members
//! whose names are either blank-padded, `/<offset>` into the long names, or
//! BSD ` #1/<len>` style.

use std::path::{Path, PathBuf};

use mold_common::mapped_file::MappedFile;
use mold_common::{fatal, warn};

use crate::context::{Archive, ArchiveMember, CoffObject, CoffSection, ImportEntry, RawSymbol};
use crate::filetype::FileType;
use crate::pe::{
    self, AuxSectionDef, CoffHeader, IMAGE_SYM_CLASS_EXTERNAL, IMAGE_SYM_CLASS_FILE,
    IMAGE_SYM_CLASS_LABEL, IMAGE_SYM_CLASS_STATIC, IMAGE_SYM_CLASS_WEAK_EXTERNAL, Relocation,
    SectionHeader, SymbolEntry,
};

/// Normalized symbol-table entry. Classic COFF uses 18-byte entries with a
/// 16-bit section number; `/bigobj` uses 20-byte entries with a 32-bit
/// section number. Names, values and classes are laid out identically.
struct NormEntry {
    short: [u8; 8],
    value: u32,
    section_number: i32,
    storage_class: u8,
    num_aux: u8,
}

impl NormEntry {
    fn parse_std(data: &[u8]) -> Option<Self> {
        let e = SymbolEntry::parse(data)?;
        Some(Self {
            short: e.name_short,
            value: e.value,
            section_number: e.section_number as i32,
            storage_class: e.storage_class,
            num_aux: e.num_aux,
        })
    }

    fn parse_bigobj(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }
        let mut short = [0u8; 8];
        short.copy_from_slice(&data[0..8]);
        Some(Self {
            short,
            value: pe::read_u32(&data[8..12]),
            section_number: i32::from_le_bytes(data[12..16].try_into().unwrap()),
            storage_class: data[18],
            num_aux: data[19],
        })
    }

    fn long_name_offset(&self) -> Option<u32> {
        if self.short[0..4] == [0, 0, 0, 0] {
            Some(u32::from_le_bytes(self.short[4..8].try_into().unwrap()))
        } else {
            None
        }
    }

    fn short_name(&self) -> &[u8] {
        let len = self.short.iter().position(|&c| c == 0).unwrap_or(8);
        &self.short[..len]
    }
}

pub fn detect(data: &[u8]) -> FileType {
    if data.is_empty() {
        return FileType::Empty;
    }
    if data.len() >= 8 && (&data[..8] == b"!<arch>\n" || &data[..8] == b"!<thin>\n") {
        return FileType::CoffArchive;
    }
    if pe::is_pe_file(data) {
        return FileType::PeFile;
    }
    if pe::is_coff_object(data) {
        return FileType::CoffObj;
    }
    FileType::Unknown
}

fn strtab_slice(
    data: &[u8],
    symtab_off: usize,
    num_syms: usize,
    entry_size: usize,
) -> &'static [u8] {
    let off = symtab_off + num_syms * entry_size;
    if off + 4 > data.len() {
        return &[];
    }
    let size = pe::read_u32(&data[off..off + 4]) as usize;
    if size < 4 || off + size > data.len() {
        return &[];
    }
    // SAFETY: the caller passes mapped input that lives for the link.
    unsafe { std::slice::from_raw_parts(data.as_ptr().add(off), size) }
}

fn string_from_table<'a>(strtab: &'a [u8], offset: u32) -> &'a [u8] {
    let off = offset as usize;
    if off >= strtab.len() {
        return b"";
    }
    pe::cstr_at(&strtab[off..])
}

/// Parses a COFF object whose bytes live in `data`. Both classic COFF and
/// `/bigobj` objects (LLVM emits the latter) are accepted.
/// Parses a COFF object into a standalone `CoffObject` without touching
/// global state, so archive members can be parsed on worker threads and
/// merged in order afterwards. Returns the object and its COFF machine.
pub fn parse_coff_bytes(name: &Path, data: &'static [u8]) -> (CoffObject, u16) {
    let bigobj = pe::is_bigobj_object(data);
    // Classic header fields, or the `/bigobj` equivalents (40-byte anon
    // header + u32 section count, symbol pointer and symbol count).
    let (machine, num_sections, symtab_offset, num_symbols, shdr_off) = if bigobj {
        if data.len() < 56 {
            fatal!("{}: file too small for COFF header", name.display());
        }
        (
            pe::read_u16(&data[6..8]),
            pe::read_u32(&data[44..48]) as usize,
            pe::read_u32(&data[48..52]),
            pe::read_u32(&data[52..56]),
            56usize,
        )
    } else {
        let hdr = CoffHeader::parse(data)
            .unwrap_or_else(|| fatal!("{}: file too small for COFF header", name.display()));
        (
            hdr.machine,
            hdr.num_sections as usize,
            hdr.symtab_offset,
            hdr.num_symbols,
            CoffHeader::SIZE,
        )
    };
    if machine != pe::COFF_MACHINE_AMD64
        && machine != pe::COFF_MACHINE_ARM64
        && machine != pe::COFF_MACHINE_I386
    {
        fatal!("{}: unsupported COFF machine {:#x}", name.display(), machine);
    }
    if machine == pe::COFF_MACHINE_I386 {
        fatal!("{}: i386 COFF objects are not supported (x86-64 and ARM64 only)", name.display());
    }

    if shdr_off + num_sections * SectionHeader::SIZE > data.len() {
        fatal!("{}: section headers extend beyond file", name.display());
    }

    let strtab = strtab_slice(
        data,
        symtab_offset as usize,
        num_symbols as usize,
        if bigobj { 20 } else { SymbolEntry::SIZE },
    );

    let mut obj = CoffObject {
        name: name.to_path_buf(),
        machine,
        sections: Vec::new(),
        symbols: Vec::new(),
        all_syms: Vec::new(),
        strtab,
    };

    // Sections.
    for i in 0..num_sections {
        let off = shdr_off + i * SectionHeader::SIZE;
        let shdr = SectionHeader::parse(&data[off..off + SectionHeader::SIZE])
            .unwrap_or_else(|| fatal!("{}: truncated section header", name.display()));
        let sec_name = pe::section_name(&shdr.name, strtab).to_vec();

        let contents: &'static [u8] = if shdr.raw_data_size > 0 && shdr.raw_data_ptr > 0 {
            let s = shdr.raw_data_ptr as usize;
            let e = s + shdr.raw_data_size as usize;
            if e > data.len() {
                fatal!("{}: section data extends beyond file", name.display());
            }
            unsafe { std::slice::from_raw_parts(data.as_ptr().add(s), e - s) }
        } else {
            &[]
        };

        let mut relocs = Vec::new();
        // `/bigobj` sections with more than 0xFFFF relocations set
        // `IMAGE_SCN_LNK_NRELOC_OVFL` and store the real count in the
        // virtual address of the first relocation entry.
        let (mut reloc_ptr, mut num_relocs) = (shdr.reloc_ptr as usize, shdr.num_relocs as usize);
        if num_relocs == 0xFFFF && shdr.characteristics & pe::IMAGE_SCN_LNK_NRELOC_OVFL != 0 {
            if reloc_ptr + Relocation::SIZE > data.len() {
                fatal!("{}: relocations extend beyond file", name.display());
            }
            num_relocs = pe::read_u32(&data[reloc_ptr..reloc_ptr + 4]) as usize - 1;
            reloc_ptr += Relocation::SIZE;
        }
        if num_relocs > 0 && reloc_ptr > 0 {
            let s = reloc_ptr;
            let e = s + num_relocs * Relocation::SIZE;
            if e > data.len() {
                fatal!("{}: relocations extend beyond file", name.display());
            }
            for j in 0..num_relocs {
                let off = s + j * Relocation::SIZE;
                relocs.push(
                    Relocation::parse(&data[off..off + Relocation::SIZE])
                        .unwrap_or_else(|| fatal!("{}: truncated relocation", name.display())),
                );
            }
        }

        obj.sections.push(CoffSection {
            name: sec_name,
            contents,
            characteristics: shdr.characteristics,
            size: shdr.raw_data_size as u64,
            relocs,
            is_comdat: shdr.characteristics & pe::IMAGE_SCN_LNK_COMDAT != 0,
            comdat_selection: 0,
            comdat_assoc: 0,
            output_section: None,
            rva: 0,
            file_offset: 0,
            is_alive: true,
        });
    }

    // Symbol table.
    if symtab_offset != 0 && num_symbols != 0 {
        parse_symbols(&mut obj, name, data, symtab_offset, num_symbols, bigobj);
    }

    (obj, machine)
}

fn parse_symbols(
    obj: &mut CoffObject,
    name: &Path,
    data: &[u8],
    symtab_offset: u32,
    num_symbols: u32,
    bigobj: bool,
) {
    let num_syms = num_symbols as usize;
    let base = symtab_offset as usize;
    let entry_size = if bigobj { 20 } else { SymbolEntry::SIZE };
    if base + num_syms * entry_size > data.len() {
        fatal!("{}: symbol table extends beyond file", name.display());
    }
    let strtab = obj.strtab;
    let num_sections = obj.sections.len() as i32;

    // Worst case: every slot is a symbol.
    obj.all_syms.reserve(num_syms);
    let mut sec_max: Vec<u32> = vec![0; num_sections.max(0) as usize];

    let mut i = 0;
    while i < num_syms {
        let off = base + i * entry_size;
        let entry = if bigobj {
            NormEntry::parse_bigobj(&data[off..off + entry_size])
        } else {
            NormEntry::parse_std(&data[off..off + entry_size])
        }
        .unwrap();
        let name: Vec<u8> = match entry.long_name_offset() {
            Some(o) => string_from_table(strtab, o).to_vec(),
            None => entry.short_name().to_vec(),
        };
        let is_weak = entry.storage_class == IMAGE_SYM_CLASS_WEAK_EXTERNAL;

        if entry.section_number > 0
            && entry.section_number <= num_sections
            && entry.storage_class == IMAGE_SYM_CLASS_EXTERNAL
        {
            let idx = (entry.section_number - 1) as usize;
            sec_max[idx] = sec_max[idx].max(entry.value + 1);
        }

        let raw = RawSymbol {
            name: name.clone(),
            value: entry.value,
            section_idx: entry.section_number,
            storage_class: entry.storage_class,
            is_weak,
            is_comdat: false,
        };
        obj.all_syms.push(raw.clone());
        let slot = obj.all_syms.len() - 1;

        for _ in 0..entry.num_aux {
            i += 1;
            if i >= num_syms {
                break;
            }
            // Aux records occupy a slot so raw indices stay aligned.
            obj.all_syms.push(RawSymbol {
                name: Vec::new(),
                value: 0,
                section_idx: 0,
                storage_class: 0,
                is_weak: false,
                is_comdat: false,
            });
            let aoff = base + i * entry_size;
            // Section-definition aux carries COMDAT selection.
            if entry.storage_class == IMAGE_SYM_CLASS_STATIC && entry.section_number > 0 {
                if let Some(aux) = AuxSectionDef::parse(&data[aoff..aoff + SymbolEntry::SIZE]) {
                    if aux.selection != 0 {
                        let sidx = (entry.section_number - 1) as usize;
                        if sidx < obj.sections.len() {
                            obj.sections[sidx].comdat_selection = aux.selection;
                            obj.sections[sidx].comdat_assoc = aux.number;
                            obj.all_syms[slot].is_comdat = true;
                        }
                    }
                }
            }
            if entry.storage_class == IMAGE_SYM_CLASS_WEAK_EXTERNAL {
                obj.all_syms[slot].is_weak = true;
            }
        }
        i += 1;

        if entry.storage_class == IMAGE_SYM_CLASS_FILE || entry.section_number < 0 {
            continue;
        }
        if entry.section_number == 0 && entry.storage_class != IMAGE_SYM_CLASS_EXTERNAL && !is_weak
        {
            continue;
        }
        if entry.storage_class == IMAGE_SYM_CLASS_STATIC && entry.section_number > 0 {
            continue;
        }
        // Local labels (AArch64 mapping symbols `$x`/`$d`, etc.) never
        // participate in symbol resolution; interning them would collide
        // across objects.
        if entry.storage_class == IMAGE_SYM_CLASS_LABEL {
            continue;
        }
        if name.is_empty() {
            continue;
        }
        obj.symbols.push(raw);
    }

    // BSS sections with no raw data size their extent from symbol values.
    for (idx, max) in sec_max.iter().enumerate() {
        if *max > 0 {
            let sec = &mut obj.sections[idx];
            if sec.is_bss() && sec.size == 0 {
                sec.size = *max as u64;
            }
        }
    }
}

fn read_ar_num(s: &[u8]) -> u64 {
    let mut n = 0u64;
    for &c in s.iter().take(10) {
        if c.is_ascii_digit() {
            n = n * 10 + (c - b'0') as u64;
        }
    }
    n
}

/// Parses a SysV archive into `ctx.archives`.
/// Parses an archive into a standalone `Archive` without touching global
/// state, so input files can be read on worker threads and merged in
/// command-line order afterwards.
pub fn parse_archive(mf: &'static MappedFile) -> Archive {
    let data = mf.data();
    let mut archive = Archive {
        name: mf.name.clone(),
        mf,
        members: Vec::new(),
        symbol_to_member: hashbrown::HashMap::new(),
        longnames_offset: 0,
        longnames_size: 0,
        extract_all: false,
    };

    let mut pos = 8usize;
    // Linker members (`/`) and long names (`//`) precede real members.
    struct LinkerMember {
        data_off: usize,
        size: usize,
    }
    let mut linker_members: Vec<LinkerMember> = Vec::new();

    while pos + 60 <= data.len() {
        if &data[pos..pos + 8] == b"!<arch>\n" {
            break;
        }
        if &data[pos + 58..pos + 60] != b"`\n" {
            break;
        }
        let size = read_ar_num(&data[pos + 48..pos + 58]) as usize;
        let mut name = &data[pos..pos + 16];
        while name.last() == Some(&b' ') || name.last() == Some(&b'/') && name.len() > 1 {
            // Trim padding spaces, keeping a bare "/" intact.
            if name.last() == Some(&b' ') {
                name = &name[..name.len() - 1];
            } else {
                break;
            }
        }
        if name == b"/" {
            linker_members.push(LinkerMember { data_off: pos + 60, size });
        } else if name == b"//" {
            archive.longnames_offset = pos + 60;
            archive.longnames_size = size;
        } else {
            break;
        }
        pos += 60 + size;
        if pos & 1 == 1 {
            pos += 1;
        }
    }

    // Regular members.
    while pos + 60 <= data.len() {
        if &data[pos..pos + 8] == b"!<arch>\n" {
            break;
        }
        if &data[pos + 58..pos + 60] != b"`\n" {
            break;
        }
        let mut size = read_ar_num(&data[pos + 48..pos + 58]) as usize;
        let header_offset = pos;
        let mut data_start = pos + 60;

        let raw_name = &data[pos..pos + 16];
        let mut end = 16;
        while end > 0 && raw_name[end - 1] == b' ' {
            end -= 1;
        }
        let mut member_name = raw_name[..end].to_vec();
        // Strip trailing '/' used by SysV short names ("foo.o/").
        if member_name.last() == Some(&b'/') && member_name.len() > 1 {
            member_name.pop();
        }

        if member_name.first() == Some(&b'/') && member_name.len() > 1 {
            // "/<offset>" into the long-name table.
            let off: usize = std::str::from_utf8(&member_name[1..])
                .unwrap_or("")
                .trim()
                .parse()
                .unwrap_or(usize::MAX);
            if off != usize::MAX && archive.longnames_offset != 0 && off < archive.longnames_size {
                let base = archive.longnames_offset + off;
                let rest = &data[base..archive.longnames_offset + archive.longnames_size];
                let len = memchr::memchr2(b'/', b'\n', rest).unwrap_or(rest.len());
                member_name = rest[..len].to_vec();
                if member_name.last() == Some(&b'/') {
                    member_name.pop();
                }
            }
        } else if member_name.starts_with(b"#1/") {
            let len: usize =
                std::str::from_utf8(&member_name[3..]).unwrap_or("").trim().parse().unwrap_or(0);
            if len > 0 && data_start + len <= data.len() {
                member_name = data[data_start..data_start + len].to_vec();
                while member_name.last() == Some(&0) {
                    member_name.pop();
                }
                data_start += len;
                size -= len;
            }
        }

        if data_start + size <= data.len() {
            archive.members.push(ArchiveMember {
                name: member_name,
                offset: data_start,
                size,
                header_offset,
                extracted: false,
            });
        }
        pos = data_start + size;
        if pos & 1 == 1 {
            pos += 1;
        }
    }

    for (n, lm) in linker_members.iter().enumerate() {
        // Per SysV convention the first linker member uses 4-byte
        // big-endian offsets; a second one, if present, uses 8-byte.
        parse_linker_member(&mut archive, lm.data_off, lm.size, n > 0);
    }
    archive
}

/// Big-endian symbol index of a SysV linker member.
fn parse_linker_member(archive: &mut Archive, data_off: usize, size: usize, is_second: bool) {
    let data = archive.mf.data();
    if data_off + size > data.len() || size < 4 {
        return;
    }
    let mem = &data[data_off..data_off + size];
    let num = u32::from_be_bytes([mem[0], mem[1], mem[2], mem[3]]) as usize;
    // The first linker member uses 4-byte offsets; a second one, if
    // present, uses 8-byte offsets.
    let off_size = if is_second { 8 } else { 4 };
    if 4 + num * off_size > mem.len() {
        return;
    }
    let strtab = &mem[4 + num * off_size..];
    let mut names: Vec<&[u8]> = Vec::with_capacity(num);
    let mut pos = 0;
    while names.len() < num && pos < strtab.len() {
        let end = memchr::memchr(0, &strtab[pos..]).map(|i| pos + i).unwrap_or(strtab.len());
        names.push(&strtab[pos..end]);
        pos = end + 1;
    }
    if names.len() != num {
        return;
    }
    // member_offset points at the member header; match it via an offset
    // map instead of a linear scan (archives like LLVM's have thousands
    // of symbols times members).
    let by_offset: hashbrown::HashMap<usize, usize> =
        archive.members.iter().enumerate().map(|(j, m)| (m.header_offset, j)).collect();
    for i in 0..num {
        let member_offset = if off_size == 8 {
            u64::from_be_bytes(mem[4 + i * 8..12 + i * 8].try_into().unwrap()) as usize
        } else {
            u32::from_be_bytes(mem[4 + i * 4..8 + i * 4].try_into().unwrap()) as usize
        };
        if let Some(&j) = by_offset.get(&member_offset) {
            archive.symbol_to_member.entry(names[i].to_vec()).or_insert(j);
        }
    }
}

/// Slices an archive member's bytes and joins its display name, without
/// touching global state. Used to parse members on worker threads.
pub fn member_bytes(ar: &Archive, member_idx: usize) -> Option<(&'static [u8], PathBuf)> {
    let m = ar.members.get(member_idx)?;
    let data = ar.mf.data();
    if m.offset + m.size > data.len() {
        return None;
    }
    // SAFETY: the archive mapping lives for the whole link.
    let bytes: &'static [u8] =
        unsafe { std::slice::from_raw_parts(data.as_ptr().add(m.offset), m.size) };
    if !pe::is_coff_object(bytes) {
        return None;
    }
    let name = ar.name.join(Path::new(&String::from_utf8_lossy(&m.name).into_owned()));
    Some((bytes, name))
}

/// Parses `.idata` import descriptors out of a COFF object: the DLL name
/// from `.idata$7` and hint/name pairs from `.idata$6`.
///
/// MinGW short-import members name the thunk and the import differently:
/// `.idata$6` holds the real import name (`_set_app_type`) while the
/// `.text` thunk is `__set_app_type`. The thunk is what callers reference,
/// so entries pair each `.text` thunk with its import name.
pub fn parse_import_entries(obj: &CoffObject, data: &[u8]) -> Vec<ImportEntry> {
    let mut dll_name: Vec<u8> = Vec::new();
    let mut names: Vec<(Vec<u8>, u16)> = Vec::new();

    for sec in &obj.sections {
        if sec.name == b".idata$7" && !sec.contents.is_empty() {
            // Dlltool import members hold the plain DLL name here, but
            // GNU-ld-style members hold an import *directory entry* (binary
            // RVAs). Only accept plausible strings so the latter falls
            // through to the `_head_` sibling hunt below.
            let s = pe::cstr_at(sec.contents);
            if !s.is_empty() && s.iter().all(|&c| (0x20..0x7F).contains(&c)) {
                dll_name = s.to_vec();
            }
        }
        if sec.name == b".idata$6" && sec.contents.len() >= 2 {
            let hint = u16::from_le_bytes([sec.contents[0], sec.contents[1]]);
            let sym = pe::cstr_at(&sec.contents[2..]).to_vec();
            if !sym.is_empty() {
                names.push((sym, hint));
            }
        }
    }

    // Fall back to `__imp_` symbols when `.idata$6` is absent.
    if names.is_empty() {
        for sym in &obj.symbols {
            if let Some(rest) = sym.name.strip_prefix(b"__imp_") {
                names.push((rest.to_vec(), 0));
            }
        }
    }
    let _ = data;

    let thunks = thunk_symbols(obj);
    // Pure data-import members (empty `.text`, e.g. MinGW's `__imp_X`
    //-only members) have hint/names but no thunks. Pair leftover names
    // with defined `__imp_Y` symbols in order so the real pointer gets a
    // synthetic import entry.
    let mut bare_imp: Vec<Vec<u8>> = Vec::new();
    for sym in &obj.symbols {
        if sym.section_idx <= 0 {
            continue;
        }
        let Some(rest) = sym.name.strip_prefix(b"__imp_") else {
            continue;
        };
        if thunks.iter().any(|t| t == rest) {
            continue;
        }
        let sidx = (sym.section_idx - 1) as usize;
        if sidx < obj.sections.len() && obj.sections[sidx].name.starts_with(b".idata") {
            bare_imp.push(rest.to_vec());
        }
    }
    names
        .into_iter()
        .enumerate()
        .map(|(i, (import_name, ordinal_hint))| {
            // Pair each import name with its thunk. Short-import members
            // carry exactly one of each; when they differ (e.g. thunk
            // `__set_app_type` vs import `_set_app_type`), the thunk is
            // what callers reference.
            let symbol_name = match thunks.get(i).cloned() {
                Some(t) => t,
                None => {
                    let j = i.saturating_sub(thunks.len());
                    bare_imp.get(j).cloned().unwrap_or_else(|| {
                        thunks.first().cloned().unwrap_or_else(|| import_name.clone())
                    })
                }
            };
            ImportEntry { symbol_name, import_name, dll_name: dll_name.clone(), ordinal_hint }
        })
        .collect()
}

/// Defined extern symbols living in a `.text` thunk section: the names
/// callers reference for imports. Excludes `__imp_` pointers and the
/// archive anchor symbols (`_head_*`, `hname`, `fthunk`).
pub fn thunk_symbols(obj: &CoffObject) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for sym in &obj.symbols {
        if sym.section_idx <= 0 || sym.name.starts_with(b"__imp_") {
            continue;
        }
        let sidx = (sym.section_idx - 1) as usize;
        if sidx >= obj.sections.len() {
            continue;
        }
        if obj.sections[sidx].name != b".text" {
            continue;
        }
        if sym.name.starts_with(b"_head_") || sym.name == b"hname" || sym.name == b"fthunk" {
            continue;
        }
        out.push(sym.name.clone());
    }
    out
}

/// Whether an object is an import-library member rather than real code:
/// it carries `.idata` import descriptors (MinGW short-import members have
/// a `.text` thunk plus `.idata$4/5/6/7`; the head/tail members are pure
/// `.idata`).
pub fn is_import_member(obj: &CoffObject) -> bool {
    obj.sections.iter().any(|s| s.name.starts_with(b".idata"))
}

/// Warns on PE executables passed as inputs (v1 cannot link against them).
pub fn warn_pe_file(path: &Path) {
    warn!("{}: PE executables cannot be used as linker inputs yet; skipping", path.display());
}

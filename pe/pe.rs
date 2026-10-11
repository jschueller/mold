//! On-disk PE/COFF format: constants, raw structs and name helpers.
//!
//! Ported from `src/pe-coff/pe-coff.h`. Raw values are read with explicit
//! little-endian loads so that unaligned file contents never cause UB.

pub const COFF_MACHINE_AMD64: u16 = 0x8664;
pub const COFF_MACHINE_I386: u16 = 0x014C;
pub const COFF_MACHINE_ARM64: u16 = 0xAA64;

pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
pub const IMAGE_FILE_DLL: u16 = 0x2000;

pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const IMAGE_SCN_LNK_COMDAT: u32 = 0x0000_1000;
pub const IMAGE_SCN_LNK_NRELOC_OVFL: u32 = 0x0100_0000;
pub const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

pub const IMAGE_REL_AMD64_ABSOLUTE: u16 = 0x0000;
pub const IMAGE_REL_AMD64_ADDR64: u16 = 0x0001;
pub const IMAGE_REL_AMD64_ADDR32: u16 = 0x0002;
pub const IMAGE_REL_AMD64_ADDR32NB: u16 = 0x0003;
pub const IMAGE_REL_AMD64_REL32: u16 = 0x0004;
pub const IMAGE_REL_AMD64_REL32_1: u16 = 0x0005;
pub const IMAGE_REL_AMD64_REL32_2: u16 = 0x0006;
pub const IMAGE_REL_AMD64_REL32_3: u16 = 0x0007;
pub const IMAGE_REL_AMD64_REL32_4: u16 = 0x0008;
pub const IMAGE_REL_AMD64_REL32_5: u16 = 0x0009;

// ARM64 relocations.
pub const IMAGE_REL_ARM64_ABSOLUTE: u16 = 0x0000;
pub const IMAGE_REL_ARM64_ADDR32: u16 = 0x0001;
pub const IMAGE_REL_ARM64_ADDR32NB: u16 = 0x0002;
pub const IMAGE_REL_ARM64_BRANCH26: u16 = 0x0003;
pub const IMAGE_REL_ARM64_PAGEBASE_REL21: u16 = 0x0004;
pub const IMAGE_REL_ARM64_REL21: u16 = 0x0005;
pub const IMAGE_REL_ARM64_PAGEOFFSET_12A: u16 = 0x0006;
pub const IMAGE_REL_ARM64_PAGEOFFSET_12L: u16 = 0x0007;
pub const IMAGE_REL_ARM64_SECREL: u16 = 0x0008;
pub const IMAGE_REL_ARM64_SECREL_LOW12A: u16 = 0x0009;
pub const IMAGE_REL_ARM64_SECREL_HIGH12A: u16 = 0x000A;
pub const IMAGE_REL_ARM64_SECREL_LOW12L: u16 = 0x000B;
pub const IMAGE_REL_ARM64_TOKEN: u16 = 0x000C;
pub const IMAGE_REL_ARM64_SECTION: u16 = 0x000D;
pub const IMAGE_REL_ARM64_ADDR64: u16 = 0x000E;
pub const IMAGE_REL_ARM64_BRANCH19: u16 = 0x000F;
pub const IMAGE_REL_ARM64_BRANCH14: u16 = 0x0010;
pub const IMAGE_REL_ARM64_REL32: u16 = 0x0011;

pub const IMAGE_SYM_CLASS_EXTERNAL: u8 = 2;
pub const IMAGE_SYM_CLASS_STATIC: u8 = 3;
pub const IMAGE_SYM_CLASS_LABEL: u8 = 6;
pub const IMAGE_SYM_CLASS_FILE: u8 = 103;
pub const IMAGE_SYM_CLASS_WEAK_EXTERNAL: u8 = 105;

pub const IMAGE_SYM_UNDEFINED: i16 = 0;
pub const IMAGE_SYM_ABSOLUTE: i16 = -1;
pub const IMAGE_SYM_DEBUG: i16 = -2;

pub const PE32_PLUS_MAGIC: u16 = 0x020B;

pub const IMAGE_SUBSYSTEM_UNKNOWN: u16 = 0;
pub const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;
pub const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
pub const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;
pub const IMAGE_SUBSYSTEM_POSIX_CUI: u16 = 7;
pub const IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: u16 = 16;

pub const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;
pub const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
pub const IMAGE_DLLCHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
pub const IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: u16 = 0x8000;

pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
pub const IMAGE_REL_BASED_DIR64: u16 = 10;

pub const BASE_RELOC_TYPE_SHIFT: u32 = 12;

pub const FILE_ALIGNMENT: u64 = 0x200;
pub const SECTION_ALIGNMENT: u64 = 0x1000;
pub const DEFAULT_IMAGE_BASE: u64 = 0x14000_0000;

/// Raw COFF file header (20 bytes).
#[derive(Clone, Copy, Debug)]
pub struct CoffHeader {
    pub machine: u16,
    pub num_sections: u16,
    pub timestamp: u32,
    pub symtab_offset: u32,
    pub num_symbols: u32,
    pub opt_header_size: u16,
    pub characteristics: u16,
}

impl CoffHeader {
    pub const SIZE: usize = 20;

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            machine: read_u16(&data[0..2]),
            num_sections: read_u16(&data[2..4]),
            timestamp: read_u32(&data[4..8]),
            symtab_offset: read_u32(&data[8..12]),
            num_symbols: read_u32(&data[12..16]),
            opt_header_size: read_u16(&data[16..18]),
            characteristics: read_u16(&data[18..20]),
        })
    }
}

/// Raw section header (40 bytes).
#[derive(Clone, Copy, Debug)]
pub struct SectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_data_size: u32,
    pub raw_data_ptr: u32,
    pub reloc_ptr: u32,
    pub linenum_ptr: u32,
    pub num_relocs: u16,
    pub num_linenums: u16,
    pub characteristics: u32,
}

impl SectionHeader {
    pub const SIZE: usize = 40;

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        let mut name = [0u8; 8];
        name.copy_from_slice(&data[0..8]);
        Some(Self {
            name,
            virtual_size: read_u32(&data[8..12]),
            virtual_address: read_u32(&data[12..16]),
            raw_data_size: read_u32(&data[16..20]),
            raw_data_ptr: read_u32(&data[20..24]),
            reloc_ptr: read_u32(&data[24..28]),
            linenum_ptr: read_u32(&data[28..32]),
            num_relocs: read_u16(&data[32..34]),
            num_linenums: read_u16(&data[34..36]),
            characteristics: read_u32(&data[36..40]),
        })
    }
}

/// Raw relocation entry (10 bytes).
#[derive(Clone, Copy, Debug)]
pub struct Relocation {
    pub virtual_address: u32,
    pub symbol_index: u32,
    pub ty: u16,
}

impl Relocation {
    pub const SIZE: usize = 10;

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        Some(Self {
            virtual_address: read_u32(&data[0..4]),
            symbol_index: read_u32(&data[4..8]),
            ty: read_u16(&data[8..10]),
        })
    }
}

/// Raw symbol table entry (18 bytes).
#[derive(Clone, Copy, Debug)]
pub struct SymbolEntry {
    pub name_short: [u8; 8],
    pub value: u32,
    pub section_number: i16,
    pub ty: u16,
    pub storage_class: u8,
    pub num_aux: u8,
}

impl SymbolEntry {
    pub const SIZE: usize = 18;

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        let mut name_short = [0u8; 8];
        name_short.copy_from_slice(&data[0..8]);
        Some(Self {
            name_short,
            value: read_u32(&data[8..12]),
            section_number: read_u16(&data[12..14]) as i16,
            ty: read_u16(&data[14..16]),
            storage_class: data[16],
            num_aux: data[17],
        })
    }

    /// Long names are stored as (0, offset) into the string table.
    pub fn long_name_offset(&self) -> Option<u32> {
        let zeroes = u32::from_le_bytes(self.name_short[0..4].try_into().unwrap());
        if zeroes == 0 {
            Some(u32::from_le_bytes(self.name_short[4..8].try_into().unwrap()))
        } else {
            None
        }
    }

    pub fn short_name(&self) -> &[u8] {
        let len = self.name_short.iter().position(|&c| c == 0).unwrap_or(8);
        &self.name_short[..len]
    }
}

/// Auxiliary section-definition record (follows a static section symbol).
#[derive(Clone, Copy, Debug)]
pub struct AuxSectionDef {
    pub length: u32,
    pub num_relocs: u16,
    pub num_linenums: u16,
    pub checksum: u32,
    pub number: u16,
    pub selection: u8,
}

impl AuxSectionDef {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < SymbolEntry::SIZE {
            return None;
        }
        Some(Self {
            length: read_u32(&data[0..4]),
            num_relocs: read_u16(&data[4..6]),
            num_linenums: read_u16(&data[6..8]),
            checksum: read_u32(&data[8..12]),
            number: read_u16(&data[12..14]),
            selection: data[14],
        })
    }
}

#[inline]
pub fn read_u16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

#[inline]
pub fn read_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[inline]
pub fn read_u64(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

pub fn is_coff_object(data: &[u8]) -> bool {
    if data.len() < CoffHeader::SIZE {
        return false;
    }
    let machine = read_u16(&data[0..2]);
    machine == COFF_MACHINE_AMD64
        || machine == COFF_MACHINE_ARM64
        || machine == COFF_MACHINE_I386
        || is_bigobj_object(data)
}

/// `/bigobj` extended COFF (e.g. LLVM objects): `Sig1 == 0`,
/// `Sig2 == 0xFFFF`, a 40-byte anon header and 20-byte symbol entries
/// with 32-bit section numbers.
pub fn is_bigobj_object(data: &[u8]) -> bool {
    if data.len() < 56 {
        return false;
    }
    read_u16(&data[0..2]) == 0
        && read_u16(&data[2..4]) == 0xFFFF
        && read_u16(&data[4..6]) >= 1
        && (read_u16(&data[6..8]) == COFF_MACHINE_AMD64
            || read_u16(&data[6..8]) == COFF_MACHINE_ARM64)
}

pub fn is_pe_file(data: &[u8]) -> bool {
    if data.len() < 64 || data[0] != b'M' || data[1] != b'Z' {
        return false;
    }
    let pe_offset = read_u32(&data[60..64]) as usize;
    if pe_offset + 4 > data.len() {
        return false;
    }
    &data[pe_offset..pe_offset + 4] == b"PE\0\0"
}

/// Section name, handling the `/<decimal offset>` long-name form.
pub fn section_name<'a>(raw: &'a [u8; 8], strtab: &'a [u8]) -> &'a [u8] {
    if raw[0] == b'/' {
        let mut off: usize = 0;
        for &c in &raw[1..] {
            if c.is_ascii_digit() {
                off = off * 10 + (c - b'0') as usize;
            } else {
                break;
            }
        }
        if off < strtab.len() {
            return cstr_at(&strtab[off..]);
        }
        return b"";
    }
    let len = raw.iter().position(|&c| c == 0).unwrap_or(8);
    &raw[..len]
}

pub fn cstr_at(data: &[u8]) -> &[u8] {
    match memchr::memchr(0, data) {
        Some(i) => &data[..i],
        None => data,
    }
}

const KNOWN_PREFIXES: &[&[u8]] = &[
    b".text",
    b".data",
    b".rdata",
    b".bss",
    b".xdata",
    b".pdata",
    b".CRT",
    b".tls",
    b".ctors",
    b".eh_frame",
    b".idata",
    b".edata",
    b".reloc",
];

/// Output section name for PE section merging:
/// `.text$mn` -> `.text`, `.refptr.X` -> `.rdata`, `.text.startup` -> `.text`.
pub fn section_prefix(name: &[u8]) -> &[u8] {
    if let Some(pos) = memchr::memchr(b'$', name) {
        return &name[..pos];
    }
    if name.starts_with(b".refptr") {
        return b".rdata";
    }
    for prefix in KNOWN_PREFIXES {
        if name.len() > prefix.len()
            && name[prefix.len()] == b'.'
            && &name[..prefix.len()] == *prefix
        {
            return &name[..prefix.len()];
        }
    }
    name
}

pub fn section_suffix(name: &[u8]) -> &[u8] {
    match memchr::memchr(b'$', name) {
        Some(pos) => &name[pos + 1..],
        None => b"",
    }
}

/// COFF per-section alignment, decoded from characteristics bits 20-23.
pub fn section_alignment(characteristics: u32) -> u64 {
    let field = (characteristics >> 20) & 0xF;
    if field == 0 {
        return 1;
    }
    let align = 1u64 << (field - 1);
    align.max(1)
}

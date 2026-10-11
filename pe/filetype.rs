//! Input file classification for PE/COFF inputs.

use mold_common::mapped_file::MappedFile;

use crate::pe::{is_coff_object, is_pe_file};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    Unknown,
    Empty,
    CoffObj,
    CoffArchive,
    PeFile,
}

pub fn get_file_type(mf: &MappedFile) -> FileType {
    let data = mf.data();
    if data.is_empty() {
        return FileType::Empty;
    }
    // Only regular archives are classified by content; thin archives name
    // their members without embedding them, so their format cannot be
    // told here (an explicit -m still routes such links correctly).
    if data.len() >= 8 && &data[..8] == b"!<arch>\n" {
        return if is_coff_archive(data) {
            FileType::CoffArchive
        } else {
            FileType::Unknown
        };
    }
    if is_pe_file(data) {
        return FileType::PeFile;
    }
    if is_coff_object(data) {
        return FileType::CoffObj;
    }
    FileType::Unknown
}

/// A regular SysV archive is COFF iff its first real member is a COFF
/// object: both toolchains start the archive with a `/` index member,
/// so the magic and member names alone cannot tell ELF and COFF apart.
fn is_coff_archive(data: &[u8]) -> bool {
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
        let mut digits = 0usize;
        let mut size = 0usize;
        while digits < 10 && data[off + 48 + digits].is_ascii_digit() {
            size = size * 10 + (data[off + 48 + digits] - b'0') as usize;
            digits += 1;
        }
        if digits == 0 {
            return false;
        }
        off += 60;
        if off + size > data.len() {
            return false;
        }
        let special =
            name == b"/" || name == b"//" || name == b"__.SYMDEF" || name == b"/SYM64/";
        if !special && size >= 2 {
            // BigObj members start with the anonymous header, whose
            // machine field sits at a different offset (this shape also
            // covers short-import members).
            if size >= 8
                && data[off] == 0
                && data[off + 1] == 0
                && data[off + 2] == 0xFF
                && data[off + 3] == 0xFF
            {
                let machine = u16::from_le_bytes([data[off + 6], data[off + 7]]);
                return machine == crate::pe::COFF_MACHINE_AMD64
                    || machine == crate::pe::COFF_MACHINE_I386
                    || machine == crate::pe::COFF_MACHINE_ARM64;
            }
            let machine = u16::from_le_bytes([data[off], data[off + 1]]);
            return machine == crate::pe::COFF_MACHINE_AMD64
                || machine == crate::pe::COFF_MACHINE_I386
                || machine == crate::pe::COFF_MACHINE_ARM64;
        }
        off += (size + 1) & !1;
    }
    false
}

/// Target name of a COFF or PE file, for `-m` dispatch. i386 objects are
/// recognized but reported as such so the driver can diagnose them.
pub fn get_pe_target(data: &[u8]) -> Option<&'static str> {
    if is_pe_file(data) {
        // Machine lives in the COFF header at the PE offset.
        if data.len() >= 64 {
            let pe_off = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap_or([0; 4])) as usize;
            if data.len() >= pe_off + 6 {
                return match u16::from_le_bytes([data[pe_off + 4], data[pe_off + 5]]) {
                    crate::pe::COFF_MACHINE_AMD64 => Some("pe-x86-64"),
                    crate::pe::COFF_MACHINE_ARM64 => Some("pe-aarch64"),
                    crate::pe::COFF_MACHINE_I386 => Some("pe-i386"),
                    _ => None,
                };
            }
        }
        return Some("pe-x86-64");
    }
    if data.len() < 2 {
        return None;
    }
    // BigObj members start with the anon header, not the machine.
    if data.len() >= 8 && data[0] == 0 && data[1] == 0 && data[2] == 0xFF && data[3] == 0xFF {
        return match u16::from_le_bytes([data[6], data[7]]) {
            crate::pe::COFF_MACHINE_AMD64 => Some("pe-x86-64"),
            crate::pe::COFF_MACHINE_ARM64 => Some("pe-aarch64"),
            _ => None,
        };
    }
    let machine = u16::from_le_bytes([data[0], data[1]]);
    match machine {
        crate::pe::COFF_MACHINE_AMD64 => Some("pe-x86-64"),
        crate::pe::COFF_MACHINE_ARM64 => Some("pe-aarch64"),
        crate::pe::COFF_MACHINE_I386 => Some("pe-i386"),
        _ => None,
    }
}

pub fn is_coff_input(mf: &MappedFile) -> bool {
    matches!(get_file_type(mf), FileType::CoffObj | FileType::CoffArchive | FileType::PeFile)
}

/// COFF machine of an object file's bytes (BigObj-aware). Zero when unknown.
pub fn pe_machine_of(data: &[u8]) -> u16 {
    if data.len() >= 8 && data[0] == 0 && data[1] == 0 && data[2] == 0xFF && data[3] == 0xFF {
        return u16::from_le_bytes([data[6], data[7]]);
    }
    if data.len() >= 2 {
        return u16::from_le_bytes([data[0], data[1]]);
    }
    0
}

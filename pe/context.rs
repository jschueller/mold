//! In-memory data structures for the PE/COFF link.
//!
//! Indices replace the C++ prototype's pointers: a symbol refers to its
//! section as `Option<SectionRef(file, section)>`, and output sections own
//! lists of such refs. All input bytes borrow from `MappedFile` with a
//! `'static` lifetime, as in the ELF and Mach-O linkers.

use std::collections::BTreeMap;
use std::path::PathBuf;

use hashbrown::HashMap;

use crate::pe::Relocation;

/// Reference to an input section: (file index, section index).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SectionRef(pub usize, pub usize);

/// A global (extern or weak-extern) COFF symbol after resolution.
#[derive(Clone, Debug)]
pub struct Symbol {
    pub name: Vec<u8>,
    pub value: u32,
    pub storage_class: u8,
    pub is_weak: bool,
    pub is_comdat: bool,
    pub is_defined: bool,
    pub is_undefined: bool,
    pub is_imported: bool,
    pub is_dll_import: bool,
    pub is_exported: bool,
    pub is_auto_imported: bool,
    /// An absolute symbol (e.g. `__ImageBase`): `resolved_value` is already
    /// a VA, so relocations must not add the image base again.
    pub is_absolute: bool,
    pub file: Option<usize>,
    pub section: Option<SectionRef>,
    pub resolved_value: u64,
    pub dll_name: Vec<u8>,
    pub import_name: Vec<u8>,
    pub ordinal_hint: u16,
}

impl Symbol {
    pub fn undefined(name: Vec<u8>) -> Self {
        Self {
            name,
            value: 0,
            storage_class: 0,
            is_weak: false,
            is_comdat: false,
            is_defined: false,
            is_undefined: true,
            is_imported: false,
            is_dll_import: false,
            is_exported: false,
            is_auto_imported: false,
            is_absolute: false,
            file: None,
            section: None,
            resolved_value: 0,
            dll_name: Vec::new(),
            import_name: Vec::new(),
            ordinal_hint: 0,
        }
    }

    pub fn is_extern(&self) -> bool {
        self.storage_class == crate::pe::IMAGE_SYM_CLASS_EXTERNAL
            || self.storage_class == crate::pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL
    }
}

/// An input section of a COFF object.
#[derive(Clone, Debug)]
pub struct CoffSection {
    pub name: Vec<u8>,
    pub contents: &'static [u8],
    pub characteristics: u32,
    pub size: u64,
    pub relocs: Vec<Relocation>,
    pub is_comdat: bool,
    pub comdat_selection: u8,
    pub comdat_assoc: u16,
    pub output_section: Option<usize>,
    pub rva: u64,
    pub file_offset: u64,
    pub is_alive: bool,
}

impl CoffSection {
    pub fn is_bss(&self) -> bool {
        self.characteristics & crate::pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0
    }

    pub fn output_name(&self) -> &[u8] {
        crate::pe::section_prefix(&self.name)
    }
}

/// A raw per-file symbol: what the object file's symbol table says before
/// global resolution. Kept per file so relocations can look symbols up by
/// raw table index (including section symbols that never enter the global
/// table).
#[derive(Clone, Debug)]
pub struct RawSymbol {
    pub name: Vec<u8>,
    pub value: u32,
    pub section_idx: i32,
    pub storage_class: u8,
    pub is_weak: bool,
    pub is_comdat: bool,
}

/// A parsed COFF object file.
#[derive(Debug)]
pub struct CoffObject {
    pub name: PathBuf,
    pub machine: u16,
    pub sections: Vec<CoffSection>,
    /// Filtered symbols (externs and defined globals).
    pub symbols: Vec<RawSymbol>,
    /// Every symbol-table slot, indexed by raw table index. Auxiliary
    /// records occupy a placeholder entry.
    pub all_syms: Vec<RawSymbol>,
    pub strtab: &'static [u8],
}

/// One member of an archive (`.a` / `.lib`).
#[derive(Debug)]
pub struct ArchiveMember {
    pub name: Vec<u8>,
    pub offset: usize,
    pub size: usize,
    pub header_offset: usize,
    pub extracted: bool,
}

/// A parsed archive file.
#[derive(Debug)]
pub struct Archive {
    pub name: PathBuf,
    pub mf: &'static mold_common::mapped_file::MappedFile,
    pub members: Vec<ArchiveMember>,
    pub symbol_to_member: HashMap<Vec<u8>, usize>,
    pub longnames_offset: usize,
    pub longnames_size: usize,
    /// `--whole-archive` was active for this archive: extract all members.
    pub extract_all: bool,
}

/// An import-library entry extracted from `.idata` sections.
#[derive(Clone, Debug)]
pub struct ImportEntry {
    /// The thunk symbol callers reference (e.g. `__set_app_type`).
    pub symbol_name: Vec<u8>,
    /// The name written to the import hint/name table, from `.idata$6`
    /// (e.g. `_set_app_type`). Usually equal to `symbol_name`.
    pub import_name: Vec<u8>,
    pub dll_name: Vec<u8>,
    pub ordinal_hint: u16,
}

/// A directly-passed import object (a `.dll.a` member given on the command
/// line rather than pulled from an archive).
#[derive(Debug)]
pub struct ImportObject {
    pub name: PathBuf,
    pub imports: Vec<ImportEntry>,
}

/// An output section: merged input sections sharing a prefix.
#[derive(Debug)]
pub struct OutputSection {
    pub name: Vec<u8>,
    pub characteristics: u32,
    pub inputs: Vec<SectionRef>,
    pub rva: u64,
    pub virtual_size: u64,
    pub raw_data_size: u64,
    pub file_offset: u64,
    pub alignment: u64,
}

impl OutputSection {
    pub fn new(name: Vec<u8>, characteristics: u32) -> Self {
        Self {
            name,
            characteristics,
            inputs: Vec::new(),
            rva: 0,
            virtual_size: 0,
            raw_data_size: 0,
            file_offset: 0,
            alignment: 4,
        }
    }
}

/// Grouped DLL imports for the `.idata` section.
#[derive(Debug, Default)]
pub struct ImportDll {
    pub dll_name: Vec<u8>,
    pub entries: Vec<usize>,
}

/// Linker command-line configuration.
#[derive(Debug, Default)]
pub struct Args {
    pub output: PathBuf,
    pub emulation: String,
    pub entry: Vec<u8>,
    pub subsystem_name: String,
    pub subsystem: u16,
    pub image_base: u64,
    pub image_base_str: String,
    pub is_dll: bool,
    pub export_all_symbols: bool,
    /// `--export-all-symbols` (or its negation) was given explicitly.
    /// DLLs auto-export by default; executables only with the explicit flag.
    pub export_all_explicit: bool,
    pub enable_auto_import: bool,
    pub enable_runtime_pseudo_reloc: bool,
    pub kill_at: bool,
    pub large_address_aware: bool,
    /// `--dynamicbase` (ASLR opt-out via `--disable-dynamicbase`).
    pub dynamic_base: bool,
    pub gc_sections: bool,
    pub strip_all: bool,
    pub library_paths: Vec<PathBuf>,
    pub exports: Vec<Vec<u8>>,
    pub chroot: PathBuf,
    pub mmap_output_file: bool,
    pub overwrite_output_file: bool,
    /// Transient `--whole-archive` state while parsing (not a setting).
    pub in_whole_archive: bool,
}

impl Default for Symbol {
    fn default() -> Self {
        Self::undefined(Vec::new())
    }
}

/// The linker's global state.
#[derive(Debug, Default)]
pub struct Context {
    pub args: Args,
    /// COFF machine of the inputs (`0` until the first object is read).
    /// Mixed-architecture links are rejected.
    pub target_machine: u16,
    pub files: Vec<CoffObject>,
    pub import_objects: Vec<ImportObject>,
    pub archives: Vec<Archive>,
    pub symbols: Vec<Symbol>,
    pub symbol_map: HashMap<Vec<u8>, usize>,
    pub output_sections: Vec<OutputSection>,
    pub output_section_map: HashMap<Vec<u8>, usize>,
    pub text_section: Option<usize>,
    pub rdata_section: Option<usize>,
    pub data_section: Option<usize>,
    pub bss_section: Option<usize>,
    pub idata_section: Option<usize>,
    pub edata_section: Option<usize>,
    pub reloc_section: Option<usize>,
    pub import_dlls: Vec<ImportDll>,
    pub export_names: Vec<(Vec<u8>, usize)>,
    pub export_dll_name: Vec<u8>,
    /// Maps `__X_iname` anchor symbols to DLL file names, filled lazily by
    /// scanning archive members (see driver::find_sibling_dll_name).
    pub iname_to_dll: HashMap<Vec<u8>, Vec<u8>>,
    pub iname_scanned: Vec<bool>,
    pub base_reloc_pages: BTreeMap<u32, Vec<(u16, u16)>>,
    /// Serialized `.reloc` blocks built from `base_reloc_pages`.
    pub base_reloc_blocks: Vec<u8>,
    /// Cached global id per `(file, all_syms index)`, built once at the
    /// start of `run_linking_passes` when the file/symbol sets are final.
    /// Global ids are append-only stable, so no invalidation is needed; a
    /// cached `None` falls back to a live lookup (covers names interned
    /// later, e.g. the pseudo-reloc list anchors).
    pub id_cache: Vec<Vec<Option<usize>>>,
    /// Runtime pseudo-reloc items: (patched slot RVA, IAT slot RVA).
    /// Slots holding the address of DLL-imported data (e.g. `.refptr`
    /// slots for `std::cout`) are rewritten by MinGW startup with the
    /// true data address; see `pseudo_reloc`.
    pub pseudo_reloc_items: Vec<(u64, u64)>,
    /// RVA of the `__RUNTIME_PSEUDO_RELOC_LIST__` blob in `.rdata`
    /// (0 when no pseudo-relocs are needed).
    pub pseudo_reloc_rva: u64,
    pub image_size: u64,
    pub headers_size: u64,
    pub entry_point_rva: u64,
    pub entry_symbol: Option<usize>,
}

impl Context {
    pub fn get_or_intern(&mut self, name: &[u8]) -> usize {
        if let Some(&id) = self.symbol_map.get(name) {
            return id;
        }
        let id = self.symbols.len();
        self.symbols.push(Symbol::undefined(name.to_vec()));
        self.symbol_map.insert(name.to_vec(), id);
        id
    }

    pub fn find(&self, name: &[u8]) -> Option<usize> {
        self.symbol_map.get(name).copied()
    }

    pub fn get_or_create_output_section(&mut self, name: &[u8], characteristics: u32) -> usize {
        if let Some(&id) = self.output_section_map.get(name) {
            self.output_sections[id].characteristics |= characteristics;
            return id;
        }
        let id = self.output_sections.len();
        self.output_sections.push(OutputSection::new(name.to_vec(), characteristics));
        self.output_section_map.insert(name.to_vec(), id);
        id
    }

    pub fn input_section(&self, r: SectionRef) -> &CoffSection {
        &self.files[r.0].sections[r.1]
    }

    pub fn input_section_mut(&mut self, r: SectionRef) -> &mut CoffSection {
        &mut self.files[r.0].sections[r.1]
    }
}

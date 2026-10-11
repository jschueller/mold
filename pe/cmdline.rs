//! Command-line parsing for the PE/COFF linker.
//!
//! Accepts the GNU-ld-compatible MinGW subset the C++ prototype supported:
//! `-m`, `--subsystem`, `--entry`, `--image-base`, `--shared`/`--dll`,
//! `--export-all-symbols`, auto-import and pseudo-reloc toggles,
//! `--kill-at`, `-o`, `-L`, `-l`, plus pass-through tolerance for ELF-only
//! flags that MinGW driver scripts may pass (e.g. `-z`, `--hash-style`).

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use mold_common::{fatal, warn};

use crate::context::Args;
use crate::pe::{
    DEFAULT_IMAGE_BASE, IMAGE_SUBSYSTEM_NATIVE, IMAGE_SUBSYSTEM_POSIX_CUI, IMAGE_SUBSYSTEM_UNKNOWN,
    IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION, IMAGE_SUBSYSTEM_WINDOWS_CUI,
    IMAGE_SUBSYSTEM_WINDOWS_GUI,
};

pub struct ParsedArgs {
    pub args: Args,
    pub input_files: Vec<PathBuf>,
    /// Per-input `--whole-archive` state, parallel to `input_files`.
    pub input_whole: Vec<bool>,
    pub libraries: Vec<OsString>,
    /// Per-library `--whole-archive` state, parallel to `libraries`.
    pub library_whole: Vec<bool>,
}

pub fn parse_subsystem(name: &str) -> u16 {
    match name.to_ascii_lowercase().as_str() {
        "windows" => IMAGE_SUBSYSTEM_WINDOWS_GUI,
        "console" => IMAGE_SUBSYSTEM_WINDOWS_CUI,
        "native" => IMAGE_SUBSYSTEM_NATIVE,
        "posix" => IMAGE_SUBSYSTEM_POSIX_CUI,
        "efi_application" => IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION,
        "boot" | "boot_application" => IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION,
        _ => IMAGE_SUBSYSTEM_UNKNOWN,
    }
}

fn takes_arg(arg: &OsStr) -> bool {
    matches!(
        arg.as_encoded_bytes(),
        b"-o"
            | b"--output"
            | b"-m"
            | b"--emulation"
            | b"--subsystem"
            | b"--entry"
            | b"-e"
            | b"--image-base"
            | b"-L"
            | b"-l"
            | b"--export"
            | b"--out-implib"
            | b"--output-def"
            | b"--major-image-version"
            | b"--minor-image-version"
            | b"--wrap"
            | b"--undefined"
            | b"--require-defined"
            | b"-y"
            | b"--trace-symbol"
            | b"-z"
            | b"--hash-style"
            | b"--dependency-file"
            | b"--retain-symbols-file"
            | b"--dynamic-list"
            | b"--defsym"
            | b"--section-start"
            | b"-T"
            | b"--section-alignment"
            | b"--threads"
            | b"-j"
            | b"--sort-section"
            | b"-plugin"
            | b"--plugin"
            | b"-plugin-opt"
    )
}

pub fn parse_args(cmdline: &[std::borrow::Cow<'static, OsStr>]) -> ParsedArgs {
    let mut args = Args {
        output: PathBuf::from("a.exe"),
        emulation: String::new(),
        subsystem: IMAGE_SUBSYSTEM_WINDOWS_CUI,
        image_base: DEFAULT_IMAGE_BASE,
        enable_auto_import: true,
        enable_runtime_pseudo_reloc: true,
        export_all_symbols: true,
        large_address_aware: true,
        dynamic_base: true,
        mmap_output_file: true,
        overwrite_output_file: false,
        ..Default::default()
    };
    let mut input_files = Vec::new();
    let mut input_whole = Vec::new();
    let mut libraries: Vec<OsString> = Vec::new();
    let mut library_whole = Vec::new();

    // Skip argv[0].
    let mut i = 1;
    while i < cmdline.len() {
        let arg = cmdline[i].as_encoded_bytes().to_vec();
        let s = String::from_utf8_lossy(&arg).into_owned();

        if s.starts_with("-Wl,") {
            for tok in s[4..].split(',') {
                if !tok.is_empty() {
                    handle_flag(&mut args, &mut libraries, tok, None);
                }
            }
            i += 1;
            continue;
        }

        if s == "-o" || s == "--output" {
            let v = next_value(cmdline, &mut i, "-o");
            args.output = PathBuf::from(v);
            i += 1;
            continue;
        }
        if let Some(v) = s.strip_prefix("-o") {
            if !v.is_empty() && !v.starts_with('=') {
                args.output = PathBuf::from(v);
                i += 1;
                continue;
            }
        }
        if s == "-m" || s == "--emulation" {
            let v = next_value(cmdline, &mut i, "-m");
            args.emulation = v.to_string_lossy().into_owned();
            i += 1;
            continue;
        }
        if s == "--subsystem" {
            let v = next_value(cmdline, &mut i, "--subsystem");
            args.subsystem_name = v.to_string_lossy().into_owned();
            i += 1;
            continue;
        }
        if let Some(v) = s.strip_prefix("--subsystem=") {
            args.subsystem_name = v.to_owned();
            i += 1;
            continue;
        }
        if s == "--entry" || s == "-e" {
            let v = next_value(cmdline, &mut i, "--entry");
            args.entry = v.as_encoded_bytes().to_vec();
            i += 1;
            continue;
        }
        if let Some(v) = s.strip_prefix("--entry=") {
            args.entry = v.as_bytes().to_vec();
            i += 1;
            continue;
        }
        if s == "--image-base" {
            let v = next_value(cmdline, &mut i, "--image-base");
            args.image_base_str = v.to_string_lossy().into_owned();
            i += 1;
            continue;
        }
        if let Some(v) = s.strip_prefix("--image-base=") {
            args.image_base_str = v.to_owned();
            i += 1;
            continue;
        }
        // Symbol versioning does not exist in PE; accept and ignore version
        // scripts so driver lines using them still link.
        if s == "--version-script" {
            next_value(cmdline, &mut i, "--version-script");
            i += 1;
            continue;
        }
        if s.starts_with("--version-script=") {
            i += 1;
            continue;
        }
        if s == "-L" {
            let v = next_value(cmdline, &mut i, "-L");
            args.library_paths.push(PathBuf::from(v));
            i += 1;
            continue;
        }
        if let Some(v) = s.strip_prefix("-L") {
            args.library_paths.push(PathBuf::from(v));
            i += 1;
            continue;
        }
        if s == "-l" {
            let v = next_value(cmdline, &mut i, "-l");
            libraries.push(v);
            library_whole.push(args.in_whole_archive);
            i += 1;
            continue;
        }
        if let Some(v) = s.strip_prefix("-l") {
            libraries.push(OsStr::new(v).to_os_string());
            library_whole.push(args.in_whole_archive);
            i += 1;
            continue;
        }
        if s == "--export" {
            let v = next_value(cmdline, &mut i, "--export");
            args.exports.push(v.as_encoded_bytes().to_vec());
            i += 1;
            continue;
        }
        if let Some(v) = s.strip_prefix("--export=") {
            args.exports.push(v.as_bytes().to_vec());
            i += 1;
            continue;
        }
        if s == "-m" || takes_arg(cmdline[i].as_ref()) && needs_skip(&s) {
            // Generic single-arg ELF passthrough: consume the value.
            i += 2;
            continue;
        }

        if s.starts_with('-') {
            if handle_flag(&mut args, &mut libraries, &s, None) {
                i += 1;
                continue;
            }
            // Consume a separate value for known two-word options.
            if takes_arg(cmdline[i].as_ref()) {
                i += 2;
                continue;
            }
            warn!("unknown option: {s}");
            i += 1;
            continue;
        }

        input_files.push(PathBuf::from(cmdline[i].clone().into_owned()));
        input_whole.push(args.in_whole_archive);
        i += 1;
    }

    if !args.subsystem_name.is_empty() {
        args.subsystem = parse_subsystem(&args.subsystem_name);
        if args.subsystem == IMAGE_SUBSYSTEM_UNKNOWN {
            fatal!("unknown subsystem: {}", args.subsystem_name);
        }
    } else if args.is_dll {
        args.subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
    }

    if !args.image_base_str.is_empty() {
        let s = args.image_base_str.trim();
        let (digits, base) = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            Some(hex) => (hex, 16),
            None if s.starts_with('0')
                && s.len() > 1
                && s[1..].chars().all(|c| c.is_ascii_digit()) =>
            {
                (s, 8)
            }
            None => (s, 10),
        };
        match u64::from_str_radix(digits, base) {
            Ok(v) => args.image_base = v,
            Err(_) => fatal!("invalid image base: {}", args.image_base_str),
        }
    }

    ParsedArgs { args, input_files, input_whole, libraries, library_whole }
}

fn next_value(cmdline: &[std::borrow::Cow<'static, OsStr>], i: &mut usize, opt: &str) -> OsString {
    *i += 1;
    if *i >= cmdline.len() {
        fatal!("{opt} requires an argument");
    }
    cmdline[*i].clone().into_owned()
}

fn needs_skip(s: &str) -> bool {
    matches!(
        s,
        "-z" | "--hash-style"
            | "--sort-section"
            | "--section-start"
            | "-T"
            | "--section-alignment"
            | "--defsym"
            | "--threads"
            | "-j"
            | "--dependency-file"
            | "--retain-symbols-file"
            | "--dynamic-list"
            | "--wrap"
            | "--undefined"
            | "--require-defined"
            | "-y"
            | "--trace-symbol"
            | "--out-implib"
            | "--output-def"
            | "--major-image-version"
            | "--minor-image-version"
            | "-plugin"
            | "--plugin"
            | "-plugin-opt"
    )
}

/// Handles a single-dash or double-dash flag. Returns true if handled.
fn handle_flag(
    args: &mut Args,
    libraries: &mut Vec<OsString>,
    s: &str,
    _extra: Option<&str>,
) -> bool {
    match s {
        "--shared" | "-shared" | "-Bshared" | "--dll" | "-Bdynamic" | "--dynamic" | "-dynamic" => {
            if s == "--shared" || s == "-shared" || s == "-Bshared" || s == "--dll" {
                args.is_dll = true;
            }
            true
        }
        "--export-all-symbols" => {
            args.export_all_symbols = true;
            args.export_all_explicit = true;
            true
        }
        "--no-export-all-symbols" | "--exclude-all-symbols" => {
            args.export_all_symbols = false;
            args.export_all_explicit = true;
            true
        }
        "--enable-auto-import" => {
            args.enable_auto_import = true;
            true
        }
        "--disable-auto-import" => {
            args.enable_auto_import = false;
            true
        }
        "--enable-runtime-pseudo-reloc" => {
            args.enable_runtime_pseudo_reloc = true;
            true
        }
        "--no-runtime-pseudo-reloc" | "--disable-runtime-pseudo-reloc" => {
            args.enable_runtime_pseudo_reloc = false;
            true
        }
        "--kill-at" => {
            args.kill_at = true;
            true
        }
        "--no-kill-at" => {
            args.kill_at = false;
            true
        }
        "--large-address-aware" => {
            args.large_address_aware = true;
            true
        }
        "--no-large-address-aware" => {
            args.large_address_aware = false;
            true
        }
        "--dynamicbase" => {
            args.dynamic_base = true;
            true
        }
        "--disable-dynamicbase" | "--no-dynamicbase" => {
            args.dynamic_base = false;
            true
        }
        "--gc-sections" | "-gc-sections" => {
            args.gc_sections = true;
            true
        }
        "--no-gc-sections" | "-no-gc-sections" => {
            args.gc_sections = false;
            true
        }
        "--strip-all" | "-s" | "-S" => {
            args.strip_all = true;
            true
        }
        "--whole-archive" | "-whole-archive" => {
            args.in_whole_archive = true;
            true
        }
        "--no-whole-archive" | "-no-whole-archive" => {
            args.in_whole_archive = false;
            true
        }
        "-Bstatic"
        | "-static"
        | "--static"
        | "--allow-shlib-undefined"
        | "-allow-shlib-undefined"
        | "--no-allow-shlib-undefined"
        | "-no-allow-shlib-undefined"
        | "--no-fork"
        | "--fork"
        | "-report-all"
        | "--error-limit"
        | "--no-error-limit"
        | "--warn-common"
        | "--no-warn-common"
        | "--warn-shared-text"
        | "--no-warn-shared-text"
        | "--warn-multiple-definition"
        | "--no-warn-multiple-definition"
        | "--fatal-warnings"
        | "--no-fatal-warnings"
        | "--compress-debug-sections"
        | "--no-compress-debug-sections"
        | "--build-id"
        | "--no-build-id"
        | "--eh-frame-hdr"
        | "--no-eh-frame-hdr"
        | "--enable-new-dtags"
        | "--disable-new-dtags"
        | "--cref"
        | "--no-cref"
        | "--check-sections"
        | "--no-check-sections"
        | "--accept-unknown-input-arch"
        | "--no-accept-unknown-input-arch"
        | "--print-output-format"
        | "--print-memory-usage"
        | "--stats"
        | "--perf"
        | "--time"
        | "--repro"
        | "-repro"
        | "--allow-multiple-definition"
        | "--no-allow-multiple-definition"
        | "--warn-once"
        | "--no-warn-once"
        | "--detect-odr-violations"
        | "--no-detect-odr-violations"
        | "--push-state"
        | "--pop-state"
        | "--as-needed"
        | "--no-as-needed"
        | "--sort-common"
        | "--no-sort-common"
        | "--add-needed"
        | "--no-add-needed"
        | "--copy-dt-needed-entries"
        | "--no-copy-dt-needed-entries"
        | "--no-undefined"
        | "--no-warn-search-mismatch"
        | "--warn-search-mismatch"
        | "--nxcompat"
        | "--nx-compat"
        | "--no-nxcompat"
        | "--no-nx-compat"
        | "--enable-auto-image-base"
        | "--disable-auto-image-base"
        | "--high-entropy-va"
        | "--no-high-entropy-va"
        | "--tsaware"
        | "--no-tsaware"
        | "-r"
        | "--relocatable" => true,
        _ => {
            if s.starts_with("--threads=") || s.starts_with("-j") {
                return true;
            }
            // -Olevel tunes the linker's own optimizations; accepted for
            // GCC compatibility (currently no observable effect).
            if let Some(level) = s.strip_prefix("-O") {
                if level.is_empty() || level.bytes().all(|c| c.is_ascii_digit() || c == b's') {
                    return true;
                }
            }
            if s.starts_with("--hash-style=")
                || s.starts_with("--sort-section=")
                || s.starts_with("--sort-common=")
                || s.starts_with("--section-start=")
                || s.starts_with("--section-alignment=")
                || s.starts_with("--defsym=")
                || s.starts_with("--dependency-file=")
                || s.starts_with("--retain-symbols-file=")
                || s.starts_with("--dynamic-list=")
                || s.starts_with("--wrap=")
                || s.starts_with("--undefined=")
                || s.starts_with("-plugin")
                || s.starts_with("--plugin")
            {
                return true;
            }
            if s == "-z" {
                return true;
            }
            let _ = libraries;
            false
        }
    }
}

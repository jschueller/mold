//! Runs the shell tests of the format the host builds programs for. The
//! Mach-O tests drive Apple's toolchain, which only macOS has, and the ELF
//! tests need a toolchain that makes ELF programs, which macOS lacks. The
//! PE tests drive the MinGW cross toolchains wherever they are installed.

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(target_os = "macos")]
    return mold_tests::macho::run(
        &Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("tests/macho"),
        Path::new(env!("CARGO_BIN_EXE_mold")),
    );

    #[cfg(not(target_os = "macos"))]
    {
        // MOLD_TEST_SUITE selects which suites run: "elf", "pe" or
        // "all" (the default). Selected suites always all run, so one
        // failure cannot mask another.
        let suite = std::env::var("MOLD_TEST_SUITE").unwrap_or_else(|_| "all".to_owned());
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let mold = Path::new(env!("CARGO_BIN_EXE_mold"));
        let mut code = ExitCode::SUCCESS;
        if suite == "all" || suite == "elf" {
            if mold_tests::elf::run(&root.join("tests/elf"), mold) != ExitCode::SUCCESS {
                code = ExitCode::FAILURE;
            }
        }
        if suite == "all" || suite == "pe" {
            if mold_tests::pe::run(&root.join("tests/pe"), mold) != ExitCode::SUCCESS {
                code = ExitCode::FAILURE;
            }
        }
        code
    }
}

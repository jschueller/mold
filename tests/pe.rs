//! The PE/COFF (MinGW) tests' targets: x86_64-windows and
//! aarch64-windows, enabled when their cross compilers are installed.
//! x86_64 programs also run, under wine when it is installed;
//! AArch64 programs are link-checked only.

use std::env;
use std::path::Path;
use std::process::ExitCode;

use crate::{
    Mode, Options, Target, fail, make_jobs, parse_options, prepare_work_dir, print_inventory,
    print_summary, run_jobs, selected_scripts,
};

struct TargetSpec {
    machine: &'static str,
    triple: &'static str,
}

const TARGETS: &[TargetSpec] = &[
    TargetSpec { machine: "x86_64", triple: "x86_64-w64-mingw32" },
    TargetSpec { machine: "aarch64", triple: "aarch64-w64-mingw32" },
];

fn command_exists(command: &str) -> bool {
    let path = Path::new(command);
    if path.components().count() > 1 {
        return path.is_file();
    }
    env::var_os("PATH")
        .is_some_and(|paths| env::split_paths(&paths).any(|dir| dir.join(command).is_file()))
}

/// The wine binary that runs x86_64 Windows programs, if any. The
/// prefixed name comes first: plain `wine` has been seen to hang where
/// the prefixed build works.
fn wine() -> Option<String> {
    ["x86_64-w64-mingw32-wine", "wine"]
        .into_iter()
        .find(|name| command_exists(name))
        .map(str::to_owned)
}

fn target(spec: &TargetSpec, wine: Option<String>) -> Target {
    Target {
        label: format!("{}-windows", spec.machine),
        arch: Some(spec.machine.to_owned()),
        env: vec![
            ("MACHINE", Some(spec.machine.to_owned())),
            ("TRIPLE", Some(spec.triple.to_owned())),
            ("WINE", wine),
        ],
    }
}

fn selected_targets(options: &Options) -> (Vec<Target>, Vec<String>) {
    let mut targets = Vec::new();
    let mut unavailable = Vec::new();

    for spec in TARGETS {
        if !command_exists(&format!("{}-gcc", spec.triple)) {
            unavailable.push(format!("{}-windows", spec.machine));
            continue;
        }
        // Only x86_64 programs can execute here; AArch64 links are
        // validated statically.
        let wine = (spec.machine == "x86_64").then(wine).flatten();
        match &options.mode {
            Mode::Native => {
                if wine.is_some() {
                    targets.push(target(spec, wine));
                } else {
                    unavailable.push(format!("{}-windows", spec.machine));
                }
            }
            Mode::Default | Mode::All => targets.push(target(spec, wine)),
            Mode::Triple(triple) => {
                let machine = triple.split('-').next().unwrap_or(triple);
                if machine == spec.machine {
                    targets.push(target(spec, wine));
                }
            }
        }
    }

    (targets, unavailable)
}

/// Runs the PE test scripts in `cases_dir` with the linker at `mold`.
/// Command line arguments are substring patterns selecting a subset of
/// tests.
pub fn run(cases_dir: &Path, mold: &Path) -> ExitCode {
    let options = parse_options();
    let work_dir = prepare_work_dir(mold).unwrap_or_else(|err| fail(err));
    let (targets, unavailable) = selected_targets(&options);
    let scripts = selected_scripts(cases_dir, &options.patterns).unwrap_or_else(|err| fail(err));
    if options.list {
        return print_inventory(&scripts, &work_dir, targets, &unavailable);
    }
    if !unavailable.is_empty() {
        eprintln!("skipping unavailable PE targets: {}", unavailable.join(", "));
    }
    let jobs = make_jobs(&scripts, &work_dir, targets, true).unwrap_or_else(|err| fail(err));
    print_summary(&run_jobs(&work_dir, jobs, &options))
}

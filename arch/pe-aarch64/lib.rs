//! The PE/COFF linker instantiated for AArch64.

/// Links for this target.
pub fn link(cmdline: mold_pe::driver::Cmdline) {
    mold_pe::driver::link(cmdline);
}

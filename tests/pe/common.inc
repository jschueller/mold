# -*- mode: sh -*-
# Shared prologue for the PE/COFF (MinGW) tests. The runner sets MACHINE
# (x86_64 or aarch64) and TRIPLE; WINE names the Windows emulator when the
# target can execute (x86_64 with wine installed) and is empty otherwise,
# in which case tests validate the link and the output statically.

export LC_ALL=C

testname=$(basename "$0" .sh)
TESTDIR=out/test/pe-$MACHINE
t=$TESTDIR/$testname
mkdir -p $t

CC="$TRIPLE-gcc"
CXX="$TRIPLE-g++"
OBJDUMP="$TRIPLE-objdump"

# The linker under test lives in the work directory (this script's cwd)
# as mold and ld.mold; -B. makes the compiler driver find it.
export PATH="$PWD:$PATH"

not() {
  if "$@"; then return 1; else return 0; fi
}

skip() {
  echo skipped
  trap - EXIT
  exit 0
}

# Runs a Windows executable, normalizing its CRLF output for assertions.
# Callers check [ -n "$WINE" ] first.
run_wine() {
  "$WINE" "$@" | tr -d '\r'
}

# Link warning-free with mold; any warning or error fails the test.
link_c() {
  out=$1; shift
  $CC -B. -fuse-ld=mold -o "$out" "$@" 2> "$t/link.log" || exit 1
  if [ -s "$t/link.log" ]; then
    cat "$t/link.log"
    echo "unexpected linker warnings"
    exit 1
  fi
}

link_cxx() {
  out=$1; shift
  $CXX -B. -fuse-ld=mold -o "$out" "$@" 2> "$t/link.log" || exit 1
  if [ -s "$t/link.log" ]; then
    cat "$t/link.log"
    echo "unexpected linker warnings"
    exit 1
  fi
}

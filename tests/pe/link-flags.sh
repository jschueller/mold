#!/usr/bin/env bash
. $(dirname $0)/common.inc

# Everyday toolchain flags must link warning-free: -O and --sort-common
# are accepted for GNU compatibility, --as-needed is tolerated, and
# -fstack-protector-strong only works if the guard symbols resolve.
cat <<EOF | $CC -o $t/prot.o -c -fstack-protector-strong -xc -
#include <stdio.h>
#include <string.h>
char buf[64];
int main() {
  strcpy(buf, "protected");
  printf("%s\n", buf);
  return 0;
}
EOF

$CC -B. -fuse-ld=mold -o $t/prot.exe $t/prot.o -Wl,-O1,--sort-common,--as-needed 2> $t/link.log || exit 1
test ! -s $t/link.log

# A version script means nothing to PE; both forms are accepted.
$CC -B. -fuse-ld=mold -o $t/prot-ver.exe $t/prot.o -Wl,--version-script=/dev/null 2> $t/link.log || exit 1
test ! -s $t/link.log
printf 'VERS_1 { global: main; local: *; };\n' > $t/prot.ver
$CC -B. -fuse-ld=mold -o $t/prot-ver2.exe $t/prot.o -Wl,--version-script -Wl,$t/prot.ver 2> $t/link.log || exit 1
test ! -s $t/link.log

if [ -n "$WINE" ]; then
  run_wine $t/prot.exe | grep -q '^protected$'
fi

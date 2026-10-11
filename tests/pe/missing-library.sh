#!/usr/bin/env bash
. $(dirname $0)/common.inc

# A missing -l library is a hard error (like GNU ld).
cat <<EOF | $CC -o $t/main.o -c -xc -
int main() { return 0; }
EOF

not $CC -B. -fuse-ld=mold -o $t/main.exe $t/main.o -lno_such_lib_xyz 2> $t/link.log
grep -q 'cannot find library' $t/link.log

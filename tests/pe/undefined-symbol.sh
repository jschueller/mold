#!/usr/bin/env bash
. $(dirname $0)/common.inc

# An undefined symbol is a hard error (like GNU ld), which CMake
# feature detection relies on.
cat <<EOF | $CC -o $t/main.o -c -xc -
int nowhere(void);
int main() { return nowhere(); }
EOF

not $CC -B. -fuse-ld=mold -o $t/main.exe $t/main.o 2> $t/link.log
grep -q 'undefined symbol' $t/link.log

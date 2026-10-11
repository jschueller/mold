#!/usr/bin/env bash
. $(dirname $0)/common.inc

# AArch64 mapping symbols ($x/$d) are local labels and must never enter
# the global symbol table: interning them warns about duplicates (every
# object defines its own) and can misresolve section-relative
# relocations to another object's address.
cat <<EOF | $CC -o $t/a.o -c -xc -
int a(void) { return 1; }
EOF

cat <<EOF | $CC -o $t/b.o -c -xc -
int a(void);
int main() { return a() - 1; }
EOF

$CC -B. -fuse-ld=mold -o $t/main.exe $t/a.o $t/b.o 2> $t/link.log || exit 1
not grep -q 'multiple definition' $t/link.log
test ! -s $t/link.log

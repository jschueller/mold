#!/usr/bin/env bash
. $(dirname $0)/common.inc

# DLLs auto-export their globals by default, like GNU ld.
cat <<EOF | $CC -o $t/lib.o -c -xc -
int exported_fn(void) { return 1; }
int data_sym = 5;
EOF

link_c $t/lib.dll $t/lib.o -shared
$OBJDUMP -p $t/lib.dll | grep -qE '\] +[0-9a-f]+ +exported_fn$'
$OBJDUMP -p $t/lib.dll | grep -qE '\] +[0-9a-f]+ +data_sym$'

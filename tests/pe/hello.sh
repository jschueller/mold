#!/usr/bin/env bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/hello.o -c -xc -
#include <stdio.h>
int main() {
  printf("hello\n");
  return 0;
}
EOF

link_c $t/hello.exe $t/hello.o

# The entry point is the CRT startup thunk, resolved and non-zero.
$OBJDUMP -f $t/hello.exe | grep -q 'start address 0x0*140001[0-9a-f]*'

# KERNEL32.dll provides the process bootstrap imports.
$OBJDUMP -p $t/hello.exe | grep -q 'DLL Name: KERNEL32.dll'

if [ -n "$WINE" ]; then
  run_wine $t/hello.exe | grep -q '^hello$'
fi

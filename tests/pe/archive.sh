#!/usr/bin/env bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/used.o -c -xc -
int used(void) { return 7; }
EOF

cat <<EOF | $CC -o $t/unused.o -c -xc -
int unused(void) { return 8; }
EOF

cat <<EOF | $CC -o $t/main.o -c -xc -
#include <stdio.h>
int used(void);
int main() {
  printf("%d\n", used());
  return 0;
}
EOF

$TRIPLE-ar rcs $t/libab.a $t/used.o $t/unused.o
link_c $t/main.exe $t/main.o $t/libab.a

# Only the referenced member is pulled in.
not $OBJDUMP -t $t/main.exe | grep -q ' unused$'

if [ -n "$WINE" ]; then
  run_wine $t/main.exe | grep -q '^7$'
fi

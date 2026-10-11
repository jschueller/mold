#!/usr/bin/env bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/add.o -c -xc -
__declspec(dllexport) int add(int a, int b) { return a + b; }
EOF

cat <<EOF | $CC -o $t/main.o -c -xc -
#include <stdio.h>
__declspec(dllimport) int add(int a, int b);
int main() {
  printf("%d\n", add(40, 2));
  return 0;
}
EOF

link_c $t/add.dll $t/add.o -shared

# mold only tolerates --out-implib; the import library comes from dlltool.
cat > $t/add.def <<EOF
LIBRARY add.dll
EXPORTS
add
EOF
$TRIPLE-dlltool --def $t/add.def --dllname add.dll --output-lib $t/libadd.dll.a || exit 1

link_c $t/main.exe $t/main.o -L$t -ladd

# The executable imports through the DLL's import library.
$OBJDUMP -p $t/main.exe | grep -q 'DLL Name: add.dll'
$OBJDUMP -p $t/add.dll | grep -qE '\] +[0-9a-f]+ +add$'

if [ -n "$WINE" ]; then
  (cd $t && run_wine main.exe) | grep -q '^42$'
fi

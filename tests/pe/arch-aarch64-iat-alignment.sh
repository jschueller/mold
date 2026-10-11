#!/usr/bin/env bash
. $(dirname $0)/common.inc

# The ILT/IAT hold 8-byte slots and must start 8-aligned; AArch64
# faults on misaligned loads (x86-64 merely tolerates them).
cat <<EOF | $CC -o $t/hello.o -c -xc -
#include <stdio.h>
int main() {
  printf("hello\n");
  return 0;
}
EOF

link_c $t/hello.exe $t/hello.o

command -v python3 > /dev/null || skip
python3 - "$t/hello.exe" <<'EOF' | grep -q ALIGNED
import struct, sys
a = open(sys.argv[1], 'rb').read()
pe = struct.unpack('<I', a[0x3c:0x40])[0]
imp_rva, _ = struct.unpack('<II', a[pe + 24 + 112 + 8:pe + 24 + 112 + 16])
n = struct.unpack('<H', a[pe + 6:pe + 8])[0]
opt = struct.unpack('<H', a[pe + 20:pe + 22])[0]
sh = pe + 24 + opt
base_va = base_rp = None
for i in range(n):
    hb = sh + i * 40
    vs, va, rs, rp = struct.unpack('<IIII', a[hb + 8:hb + 24])
    if va <= imp_rva < va + max(vs, rs, 1):
        base_va, base_rp = va, rp
assert base_va is not None
i = 0
ok = False
while True:
    d = struct.unpack('<5I', a[base_rp + (imp_rva - base_va) + i * 20:][:20])
    if d == (0, 0, 0, 0, 0):
        break
    ok = True
    if d[0] % 8 != 0 or d[4] % 8 != 0:
        ok = False
        break
    i += 1
print("ALIGNED" if ok else "MISALIGNED")
EOF

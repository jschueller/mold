#!/usr/bin/env bash
. $(dirname $0)/common.inc

# --disable-dynamicbase must clear IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
# (0x40); it is on by default and with --dynamicbase.
cat <<EOF | $CC -o $t/main.o -c -xc -
int main() { return 0; }
EOF

link_c $t/off.exe $t/main.o -Wl,--disable-dynamicbase
link_c $t/on.exe $t/main.o -Wl,--dynamicbase
link_c $t/def.exe $t/main.o

command -v python3 > /dev/null || skip
python3 - "$t/off.exe" "$t/on.exe" "$t/def.exe" <<'EOF'
import struct, sys
for path, want in [(sys.argv[1], False), (sys.argv[2], True), (sys.argv[3], True)]:
    a = open(path, 'rb').read()
    pe = struct.unpack('<I', a[0x3c:0x40])[0]
    chars = struct.unpack('<H', a[pe + 24 + 70:pe + 24 + 72])[0]
    assert (chars & 0x40 != 0) == want, (path, hex(chars))
print("dynamicbase OK")
EOF

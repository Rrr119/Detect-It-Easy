#!/usr/bin/env bash
set -euo pipefail

# Rebuild the PEzor fixtures from the upstream wrapper source.
# Usage: ZIG=/path/to/zig ./tests/samples/build_pezor_samples.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SAMPLES="$ROOT/tests/samples"
ZIG="${ZIG:-zig}"
PEZOR_URL="https://github.com/phra/PEzor.git"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

git clone --depth 1 "$PEZOR_URL" "$WORK/PEzor"

cat > "$WORK/shellcode.cpp" <<'EOF'
unsigned char buf[] = "\x90\x90\x90\x90\x31\xC0\xC3";
unsigned int buf_size = sizeof(buf);
EOF

cat > "$WORK/sleep.cpp" <<'EOF'
unsigned int sleep_time = 0;
EOF

COMMON=(
    -O3
    -static
    -std=c++17
    -Wl,--strip-all
    -Wl,--subsystem,windows
    -I"$WORK/PEzor"
    "$WORK/PEzor/inject.cpp"
    "$WORK/PEzor/PEzor.cpp"
    "$WORK/shellcode.cpp"
    "$WORK/sleep.cpp"
)

for target in x86_64 x86; do
    output="$SAMPLES/pezor-$([ "$target" = x86_64 ] && echo x64 || echo x86).exe"

    if [ "$target" = x86_64 ]; then
        defines=(-D_WIN64 -D_WIN_X64 -D_WINX64)
    else
        defines=(-D_WIN_X86)
    fi

    "$ZIG" c++ -target "$target-windows-gnu" "${COMMON[@]}" "${defines[@]}" -o "$output"
done

cat > "$WORK/clean.cpp" <<'EOF'
#include <windows.h>
int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous, LPSTR commandLine, int show) {
    return 0;
}
EOF

"$ZIG" c++ -target x86_64-windows-gnu "${COMMON[@]:0:5}" \
    -D_WIN64 -D_WIN_X64 -D_WINX64 "$WORK/clean.cpp" -o "$SAMPLES/clean-mingw-x64.exe"

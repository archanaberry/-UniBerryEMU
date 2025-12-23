#!/usr/bin/env bash
set -e

ROOT="$(pwd)"
TESTDIR="$ROOT/test"
SRCDIR="$TESTDIR/src"
OUTDIR="$TESTDIR/out"
LDDIR="$TESTDIR/ld"

mkdir -p "$SRCDIR" "$OUTDIR" "$LDDIR"

CC=${CC:-gcc}
LD=${LD:-ld}
OBJCOPY=${OBJCOPY:-objcopy}

ENTRY32=0x00100000
ENTRY16=0x00001000

usage() {
cat <<EOF
Usage:
  ./hello.sh build
  ./hello.sh clean
EOF
exit 1
}

[ $# -lt 1 ] && usage

# -------------------------------------------------
# Write C sources
# -------------------------------------------------
write_sources() {

# 16-bit SAFE C (NO globals, NO memory access)
cat > "$SRCDIR/hello16.c" <<'EOF'
void _start(void) {
    volatile unsigned short i = 0;
    for (;;) {
        i++;
    }
}
EOF

# 32/64-bit VGA hello
cat > "$SRCDIR/hello.c" <<'EOF'
volatile char *vga = (volatile char*)0xB8000;
static int pos = 0;

void putc(char c) {
    if (c == '\n') {
        pos += 160 - (pos % 160);
        return;
    }
    vga[pos++] = c;
    vga[pos++] = 0x07;
}

void puts(const char *s) {
    while (*s) putc(*s++);
}

void _start(void) {
    puts("Hello World from C flat binary!\n");
    for (;;);
}
EOF
}

# -------------------------------------------------
# Linker scripts
# -------------------------------------------------
write_ld() {

cat > "$LDDIR/link16.ld" <<EOF
ENTRY(_start)
SECTIONS {
  . = $ENTRY16;
  .text : { *(.text*) }
}
EOF

cat > "$LDDIR/link32.ld" <<EOF
ENTRY(_start)
SECTIONS {
  . = $ENTRY32;
  .text : { *(.text*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) }
  .bss : { *(.bss*) *(COMMON) }
}
EOF
}

# -------------------------------------------------
# Build helpers
# -------------------------------------------------
build16() {
    echo "[*] Building hello16.bin (16-bit flat SAFE)"

    $CC -m16 -ffreestanding -fno-pic -fno-pie -nostdlib \
        -O0 -Wall -c "$SRCDIR/hello16.c" -o "$OUTDIR/hello16.o"

    $LD -m elf_i386 -T "$LDDIR/link16.ld" \
        "$OUTDIR/hello16.o" -o "$OUTDIR/hello16.elf"

    $OBJCOPY -O binary "$OUTDIR/hello16.elf" "$OUTDIR/hello16.bin"
}

build32() {
    echo "[*] Building hello32.bin (32-bit flat)"

    $CC -m32 -ffreestanding -fno-pic -fno-pie -nostdlib \
        -O0 -Wall -c "$SRCDIR/hello.c" -o "$OUTDIR/hello32.o"

    $LD -m elf_i386 -T "$LDDIR/link32.ld" \
        "$OUTDIR/hello32.o" -o "$OUTDIR/hello32.elf"

    $OBJCOPY -O binary "$OUTDIR/hello32.elf" "$OUTDIR/hello32.bin"
}

build64() {
    echo "[*] Building hello64.bin (64-bit flat)"

    $CC -m64 -ffreestanding -fno-pic -fno-pie -nostdlib \
        -O0 -Wall -c "$SRCDIR/hello.c" -o "$OUTDIR/hello64.o"

    $LD -m elf_x86_64 -T "$LDDIR/link32.ld" \
        "$OUTDIR/hello64.o" -o "$OUTDIR/hello64.elf"

    $OBJCOPY -O binary "$OUTDIR/hello64.elf" "$OUTDIR/hello64.bin"
}

# -------------------------------------------------
# Commands
# -------------------------------------------------
case "$1" in
build)
    write_sources
    write_ld
    build16
    build32
    build64
    echo
    echo "[✓] DONE"
    tree "$OUTDIR"
    ;;
clean)
    rm -rf "$TESTDIR"
    echo "[*] Cleaned"
    ;;
*)
    usage
    ;;
esac

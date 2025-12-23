#!/usr/bin/env bash
#
# test.sh - robust build script for tiny baremetal "hello world" kernels
# - Always writes source files into test/src/
# - Attempts to build flat binaries for x86_16, x86_32, x86_64, arm32, arm64
# - If a required toolchain is missing, it SKIPS that target and continues
#
# Usage:
#   ./test.sh
#   ./test.sh --no-apt    # don't try apt installs (this script never force-exec apt; only prints suggestions)
#
set -u
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$ROOT_DIR/test/out"
SRC_DIR="$ROOT_DIR/test/src"

mkdir -p "$OUT_DIR"
mkdir -p "$SRC_DIR"

NO_APT=0
for a in "$@"; do
  case "$a" in
    --no-apt) NO_APT=1 ;;
    *) ;;
  esac
done

log() { echo "==> $*"; }
warn() { echo "!! $*" >&2; }
err() { echo "ERROR: $*" >&2; }

# ------------------------------
# 1) Always write the source files
# ------------------------------
log "Writing source files to $SRC_DIR ..."

cat > "$SRC_DIR/kernel.c" <<'C_SRC'
/* kernel.c - common minimal kernel entry */
#include <stdint.h>

extern void arch_puts(const char *s);

void kmain(void) {
    const char *msg = "Hello, world from UniNano!\n";
    arch_puts(msg);
    /* simple busy loop */
    for (;;) {
        volatile int i = 0;
        for (i = 0; i < 1000000; ++i) { __asm__ volatile("nop"); }
    }
}
C_SRC

cat > "$SRC_DIR/start_x86_64.S" <<'ASM_X64'
.global _start
.section .text
_start:
    xor %rbp, %rbp
    lea stack_top(%rip), %rsp
    call kmain
1:  hlt
    jmp 1b
.section .bss
.comm stack_top, 2048
ASM_X64

cat > "$SRC_DIR/start_x86_32.S" <<'ASM_X32'
.global _start
.section .text
_start:
    movl $stack_top, %esp
    call kmain
1:
    hlt
    jmp 1b
.section .bss
.align 4
stack_top:
    .space 2048
ASM_X32

cat > "$SRC_DIR/arch_x86_vga.c" <<'C_X86'
#include <stdint.h>
void arch_puts(const char *s) {
    volatile uint16_t *vga = (volatile uint16_t *)0xB8000;
    uint32_t pos = 0;
    while (*s) {
        char ch = *s++;
        if (ch == '\n') {
            pos = (pos / 80 + 1) * 80;
            continue;
        }
        uint8_t attr = 0x0F;
        vga[pos++] = ((uint16_t)attr << 8) | (uint8_t)ch;
        if (pos >= 80*25) pos = 0;
    }
}
C_X86

cp "$SRC_DIR/arch_x86_vga.c" "$SRC_DIR/arch_x86_vga_32.c" 2>/dev/null || true

cat > "$SRC_DIR/boot16.asm" <<'NASM16'
; 16-bit .COM (org 0x100)
bits 16
org 0x100

start:
    mov si, msg
.print_char:
    lodsb
    cmp al, 0
    je .hang
    mov ah, 0x0E
    mov bx, 0x0007
    int 0x10
    jmp .print_char
.hang:
    cli
    hlt
    jmp .hang

msg db 'Hello, world from UniNano (16-bit)!',0
times 0x100-($-$$) db 0
NASM16

cat > "$SRC_DIR/arch_arm32.c" <<'C_ARM32'
#include <stdint.h>
void arch_puts(const char *s) {
    /* ARM semihosting SYS_WRITE0 (may work in QEMU with semihosting) */
    register const char *r1 asm("r1") = s;
    register int r0 asm("r0") = 4;
    asm volatile ("mov r0, %0\n\tmov r1, %1\n\tswi 0x123456\n\t" :: "r"(r0), "r"(r1) : "r0","r1");
}
C_ARM32

cat > "$SRC_DIR/arch_arm64.c" <<'C_ARM64'
#include <stdint.h>
void arch_puts(const char *s) {
    /* AArch64 semihosting attempt - may need QEMU or debug environment */
    register const char *x1 asm("x1") = s;
    register long x0 asm("x0") = 4;
    asm volatile ("mov x0, %0\n\tmov x1, %1\n\thlt #0xF000\n\t" :: "r"(x0), "r"(x1) : "x0","x1");
}
C_ARM64

# linker scripts
cat > "$SRC_DIR/x86_64.ld" <<'LD_X64'
ENTRY(_start)
SECTIONS
{
  . = 0x00100000;
  .text : { *(.text*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) }
  .bss : { *(.bss*) *(COMMON) }
}
LD_X64

cat > "$SRC_DIR/x86_32.ld" <<'LD_X32'
ENTRY(_start)
SECTIONS
{
  . = 0x00100000;
  .text : { *(.text*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) }
  .bss : { *(.bss*) *(COMMON) }
}
LD_X32

cat > "$SRC_DIR/arm32.ld" <<'LD_ARM32'
ENTRY(_start)
SECTIONS
{
  . = 0x8000;
  .text : { *(.text*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) }
  .bss : { *(.bss*) *(COMMON) }
}
LD_ARM32

cat > "$SRC_DIR/arm64.ld" <<'LD_ARM64'
ENTRY(_start)
SECTIONS
{
  . = 0x80000;
  .text : { *(.text*) }
  .rodata : { *(.rodata*) }
  .data : { *(.data*) }
  .bss : { *(.bss*) *(COMMON) }
}
LD_ARM64

log "Source files created."

# ------------------------------
# 2) Find toolchain commands (do not fail if missing)
# ------------------------------
find_any() {
  for name in "$@"; do
    if command -v "$name" >/dev/null 2>&1; then
      echo "$name"
      return 0
    fi
  done
  echo ""
  return 1
}

X86_64_CC="$(find_any x86_64-elf-gcc x86_64-linux-gnu-gcc gcc)"
X86_32_CC="$(find_any i686-elf-gcc i386-elf-gcc i686-linux-gnu-gcc gcc)"
ARM32_CC="$(find_any arm-none-eabi-gcc arm-linux-gnueabi-gcc)"
ARM64_CC="$(find_any aarch64-none-elf-gcc aarch64-linux-gnu-gcc)"
NASM_BIN="$(find_any nasm)"
OBJCOPY="$(find_any objcopy)"
LD_BIN="$(find_any ld)"

log "Detected:"
log "  x86_64: ${X86_64_CC:-<none>}"
log "  x86_32: ${X86_32_CC:-<none>}"
log "  arm32 : ${ARM32_CC:-<none>}"
log "  arm64 : ${ARM64_CC:-<none>}"
log "  nasm  : ${NASM_BIN:-<none>}"
log "  objcopy: ${OBJCOPY:-<none>}"
log "  ld    : ${LD_BIN:-<none>}"

# If nothing found, suggest apt commands (do not auto-run unless user asked earlier)
if [ -z "$X86_64_CC" ] && [ -z "$X86_32_CC" ] && [ -z "$ARM32_CC" ] && [ -z "$ARM64_CC" ]; then
  warn "No cross-compilers detected. Builds will be skipped. To install common packages on Debian/Ubuntu try:"
  echo "  sudo apt update && sudo apt install -y gcc-multilib nasm binutils gcc-arm-none-eabi gcc-aarch64-linux-gnu"
fi

# helper choose objcopy from gcc prefix
prefix_of() {
  local cc="$1"
  [ -z "$cc" ] && { echo ""; return; }
  local base="${cc%-gcc}"
  base="${base%-clang}"
  echo "$base"
}

choose_objcopy() {
  local cc="$1"
  if [ -n "$OBJCOPY" ]; then echo "$OBJCOPY"; return; fi
  local pref
  pref="$(prefix_of "$cc")"
  if [ -n "$pref" ] && command -v "${pref}objcopy" >/dev/null 2>&1; then
    echo "${pref}objcopy"
    return
  fi
  echo "objcopy"
}

# ------------------------------
# 3) Build per-target (skip if tool missing)
# ------------------------------
build_x86_64() {
  [ -z "$X86_64_CC" ] && { log "Skipping x86_64 build (no compiler)"; return; }
  local CC="$X86_64_CC"
  local OBJC="$("$ROOT_DIR"/test_choose_objcopy.sh 2>/dev/null || true)"
  # fallback choose:
  local CH_OBJCOPY
  CH_OBJCOPY="$(choose_objcopy "$CC")"
  log "Building x86_64 with $CC (objcopy=$CH_OBJCOPY)"
  "$CC" -ffreestanding -fno-builtin -fno-pic -fno-pie -nostdlib -O2 -c "$SRC_DIR/start_x86_64.S" -o "$OUT_DIR/start_x86_64.o" || { warn "x86_64: compile start failed"; return; }
  "$CC" -ffreestanding -fno-builtin -fno-pic -fno-pie -nostdlib -O2 -c "$SRC_DIR/arch_x86_vga.c" -o "$OUT_DIR/arch_x86_vga.o" || { warn "x86_64: compile arch failed"; return; }
  "$CC" -ffreestanding -fno-builtin -fno-pic -fno-pie -nostdlib -O2 -c "$SRC_DIR/kernel.c" -o "$OUT_DIR/kernel.o" || { warn "x86_64: compile kernel failed"; return; }
  "$CC" -nostdlib -nostartfiles -T "$SRC_DIR/x86_64.ld" -o "$OUT_DIR/kernel_x86_64.elf" "$OUT_DIR/start_x86_64.o" "$OUT_DIR/arch_x86_vga.o" "$OUT_DIR/kernel.o" || { warn "x86_64: link failed"; return; }
  "$CH_OBJCOPY" -O binary "$OUT_DIR/kernel_x86_64.elf" "$OUT_DIR/kernel_x86_64.bin" || { warn "x86_64: objcopy failed"; return; }
  log "Built $OUT_DIR/kernel_x86_64.bin"
}

build_x86_32() {
  [ -z "$X86_32_CC" ] && { log "Skipping x86_32 build (no compiler)"; return; }
  local CC="$X86_32_CC"
  local CH_OBJCOPY
  CH_OBJCOPY="$(choose_objcopy "$CC")"
  log "Building x86_32 with $CC (objcopy=$CH_OBJCOPY)"
  # Some cross compilers need -m32, some are already 32-bit targets
  local M32="-m32"
  case "$CC" in
    *-elf-*|i686-elf-gcc) M32="";;
    *-linux-gnu-*) M32="-m32";;
    gcc) M32="-m32";;
  esac
  "$CC" $M32 -ffreestanding -fno-builtin -nostdlib -O2 -c "$SRC_DIR/start_x86_32.S" -o "$OUT_DIR/start_x86_32.o" || { warn "x86_32: compile start failed"; return; }
  "$CC" $M32 -ffreestanding -fno-builtin -nostdlib -O2 -c "$SRC_DIR/arch_x86_vga_32.c" -o "$OUT_DIR/arch_x86_vga_32.o" || { warn "x86_32: compile arch failed"; return; }
  "$CC" $M32 -ffreestanding -fno-builtin -nostdlib -O2 -c "$SRC_DIR/kernel.c" -o "$OUT_DIR/kernel_32.o" || { warn "x86_32: compile kernel failed"; return; }
  "$CC" $M32 -nostdlib -nostartfiles -T "$SRC_DIR/x86_32.ld" -o "$OUT_DIR/kernel_x86_32.elf" "$OUT_DIR/start_x86_32.o" "$OUT_DIR/arch_x86_vga_32.o" "$OUT_DIR/kernel_32.o" || { warn "x86_32: link failed"; return; }
  "$CH_OBJCOPY" -O binary "$OUT_DIR/kernel_x86_32.elf" "$OUT_DIR/kernel_x86_32.bin" || { warn "x86_32: objcopy failed"; return; }
  log "Built $OUT_DIR/kernel_x86_32.bin"
}

build_x86_16() {
  [ -z "$NASM_BIN" ] && { log "Skipping x86_16 build (nasm not found)"; return; }
  log "Building x86_16 (.com) with $NASM_BIN"
  "$NASM_BIN" -f bin "$SRC_DIR/boot16.asm" -o "$OUT_DIR/kernel_x86_16.com" || { warn "x86_16: nasm failed"; return; }
  log "Built $OUT_DIR/kernel_x86_16.com"
}

build_arm32() {
  [ -z "$ARM32_CC" ] && { log "Skipping arm32 build (no compiler)"; return; }
  local CC="$ARM32_CC"
  local CH_OBJCOPY
  CH_OBJCOPY="$(choose_objcopy "$CC")"
  log "Building arm32 with $CC (objcopy=$CH_OBJCOPY)"
  "$CC" -marm -ffreestanding -fno-builtin -nostdlib -O2 -c "$SRC_DIR/arch_arm32.c" -o "$OUT_DIR/arch_arm32.o" || { warn "arm32: compile arch failed"; return; }
  "$CC" -marm -ffreestanding -fno-builtin -nostdlib -O2 -c "$SRC_DIR/kernel.c" -o "$OUT_DIR/kernel_arm32.o" || { warn "arm32: compile kernel failed"; return; }
  cat > "$OUT_DIR/start_arm32.S" <<'ARM32_START'
    .global _start
    .text
_start:
    ldr r0, =stack_top
    mov sp, r0
    bl kmain
1:  b 1b
    .bss
    .space 2048
stack_top:
ARM32_START
  "$CC" -marm -ffreestanding -fno-builtin -nostdlib -O2 -c "$OUT_DIR/start_arm32.S" -o "$OUT_DIR/start_arm32.o" || { warn "arm32: compile start failed"; return; }
  "$CC" -nostdlib -T "$SRC_DIR/arm32.ld" -o "$OUT_DIR/kernel_arm32.elf" "$OUT_DIR/start_arm32.o" "$OUT_DIR/arch_arm32.o" "$OUT_DIR/kernel_arm32.o" || { warn "arm32: link failed"; return; }
  "$CH_OBJCOPY" -O binary "$OUT_DIR/kernel_arm32.elf" "$OUT_DIR/kernel_arm32.bin" || { warn "arm32: objcopy failed"; return; }
  log "Built $OUT_DIR/kernel_arm32.bin"
}

build_arm64() {
  [ -z "$ARM64_CC" ] && { log "Skipping arm64 build (no compiler)"; return; }
  local CC="$ARM64_CC"
  local CH_OBJCOPY
  CH_OBJCOPY="$(choose_objcopy "$CC")"
  log "Building arm64 with $CC (objcopy=$CH_OBJCOPY)"
  "$CC" -ffreestanding -fno-builtin -nostdlib -O2 -c "$SRC_DIR/arch_arm64.c" -o "$OUT_DIR/arch_arm64.o" || { warn "arm64: compile arch failed"; return; }
  "$CC" -ffreestanding -fno-builtin -nostdlib -O2 -c "$SRC_DIR/kernel.c" -o "$OUT_DIR/kernel_arm64.o" || { warn "arm64: compile kernel failed"; return; }
  cat > "$OUT_DIR/start_arm64.S" <<'ARM64_START'
    .global _start
    .text
_start:
    adr x0, __stack_top
    mov sp, x0
    bl kmain
1:  wfe
    b 1b
    .bss
    .space 4096
__stack_top:
ARM64_START
  "$CC" -ffreestanding -fno-builtin -nostdlib -O2 -c "$OUT_DIR/start_arm64.S" -o "$OUT_DIR/start_arm64.o" || { warn "arm64: compile start failed"; return; }
  "$CC" -nostdlib -T "$SRC_DIR/arm64.ld" -o "$OUT_DIR/kernel_arm64.elf" "$OUT_DIR/start_arm64.o" "$OUT_DIR/arch_arm64.o" "$OUT_DIR/kernel_arm64.o" || { warn "arm64: link failed"; return; }
  "$CH_OBJCOPY" -O binary "$OUT_DIR/kernel_arm64.elf" "$OUT_DIR/kernel_arm64.bin" || { warn "arm64: objcopy failed"; return; }
  log "Built $OUT_DIR/kernel_arm64.bin"
}

# perform builds (each will skip gracefully if tool missing)
build_x86_64
build_x86_32
build_x86_16
build_arm32
build_arm64

# ------------------------------
# 4) Summary
# ------------------------------
log "Build finished. Contents of test directory:"
tree -a test || ls -la test || true

log "If some targets were skipped, install appropriate cross-compilers. Example apt commands (Debian/Ubuntu):"
echo "  sudo apt update"
echo "  sudo apt install -y nasm gcc-multilib binutils gcc-arm-none-eabi gcc-aarch64-linux-gnu"

log "To run/test (examples):"
echo "  qemu-system-x86_64 -kernel $OUT_DIR/kernel_x86_64.bin -nographic"
echo "  qemu-system-i386 -kernel $OUT_DIR/kernel_x86_32.bin -nographic"
echo "  qemu-system-arm -M versatilepb -kernel $OUT_DIR/kernel_arm32.bin -serial stdio -semihosting"
echo "  qemu-system-aarch64 -M virt -kernel $OUT_DIR/kernel_arm64.bin -serial stdio -semihosting"

log "Done."

/****************************************************************/
//                                                              //
//  -------------------UniBerry EMU Engine-------------------   //
//  Created by: Archana Berry                                   //
//  Architecture: x86 (16/32/64-bit)                            //
//  Version resource: v0.001_alpha                              //
//  File: arch/8086.h                                           //
//  Type: source[architecture]                                  //
//  Desc: x86 architecture family for baremetal emulation       //
//                                                              //
//  ----------------------------------------------------------  //
//                                                              //
//  ---- Supports x86-16 (Real Mode), x86-32 (Protected    ---- //
//  ---- Mode), and x86-64 (Long Mode) with segmentation,  ---- //
//  ---- paging, and system call emulation for DOS,        ---- //
//  ---- Linux, and Windows kernel testing.                ---- //
//                                                              //
/****************************************************************/
//                                                              //
//  Patiently awaiting the release of UniBerryEMU               //
//                                                              //
/****************************************************************/

// 8086.c

/****************************************************************/
/*  arch/8086.c                                                  */
/*  UniBerry EMU Engine - x86 (16/32/64) implementation         */
/****************************************************************/

#include "8086.h"
#include "../ubemu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <assert.h>
#include <stdint.h>

/* ---------------------------
   Internal x86 Emulator
   --------------------------- */
struct X86Emulator {
    UBEContext *ube;         /* optional engine context (top-level may attach) */
    int mode;                /* 16, 32 or 64 */
    X86State state;

    bool running;
    bool tracing;

    size_t mem_size;
    uint8_t *memory;         /* flat mirror used by this module */
    uint8_t *io_ports;       /* 64KB I/O space mirror */

    uint64_t total_cycles;
    uint64_t total_instructions;
    uint64_t total_branches;

    void (*interrupt_handler)(void *user, int vector);
    void *interrupt_user;
};

/* ---------------------------
   Helpers
   --------------------------- */
static bool is_x86_64_code(const uint8_t *data, size_t size) {
    if (!data) return false;
    if (size >= sizeof(Elf64_Ehdr)) {
        const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)data;
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0 &&
            ehdr->e_ident[EI_CLASS] == ELFCLASS64) return true;
    }
    for (size_t i = 0; i + 1 < size; ++i) {
        if ((data[i] & 0xF0) == 0x40) return true; /* REX heuristic */
    }
    return false;
}

static bool is_x86_32_code(const uint8_t *data, size_t size) {
    if (!data) return false;
    if (size >= sizeof(Elf32_Ehdr)) {
        const Elf32_Ehdr *ehdr = (const Elf32_Ehdr *)data;
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0 &&
            ehdr->e_ident[EI_CLASS] == ELFCLASS32) return true;
    }
    for (size_t i = 0; i + 1 < size; ++i) {
        if (data[i] == 0xCD && data[i+1] == 0x80) return true; /* int 0x80 */
    }
    return false;
}

/* ---------------------------
   Creation / Destruction
   --------------------------- */
X86Emulator* x86_create_emulator(int mode, size_t mem_size) {
    X86Emulator *emu = calloc(1, sizeof(X86Emulator));
    if (!emu) return NULL;

    emu->mode = mode;
    emu->mem_size = (mem_size == 0) ? (2 * 1024 * 1024) : mem_size; /* default 2MB */
    emu->memory = calloc(1, emu->mem_size);
    if (!emu->memory) { free(emu); return NULL; }

    emu->io_ports = calloc(1, 65536);
    if (!emu->io_ports) { free(emu->memory); free(emu); return NULL; }

    emu->ube = NULL; /* optional */

    memset(&emu->state, 0, sizeof(X86State));
    emu->state.cs = 0x0000;
    emu->state.ds = 0x0000;
    emu->state.es = 0x0000;
    emu->state.ss = 0x0000;
    emu->state.fs = 0x0000;
    emu->state.gs = 0x0000;

    uint64_t base = (mode == 16) ? 0x0000 : 0x00000000;
    uint64_t sp = base + emu->mem_size - 0x1000;
    if (mode == 64) emu->state.gp.r[X86_REG_RSP] = sp;
    else if (mode == 32) emu->state.gp.e[X86_REG_ESP] = (uint32_t)sp;
    else emu->state.gp.e[X86_REG_ESP] = (uint32_t)sp & 0xFFFF;

    if (mode == 16) emu->state.real_mode = true;
    if (mode == 32) emu->state.protected_mode = true;
    if (mode == 64) emu->state.long_mode = true;

    return emu;
}

void x86_destroy_emulator(X86Emulator *emu) {
    if (!emu) return;
    if (emu->memory) free(emu->memory);
    if (emu->io_ports) free(emu->io_ports);
    free(emu);
}

/* ---------------------------
   Memory management
   --------------------------- */
int x86_map_memory(X86Emulator *emu, uint64_t addr, size_t size, bool read, bool write, bool exec) {
    (void)emu; (void)addr; (void)size; (void)read; (void)write; (void)exec;
    /* top-level engine manages mapping; this module keeps flat mirror */
    return 0;
}

int x86_load_binary(X86Emulator *emu, const uint8_t *data, size_t size, uint64_t load_addr) {
    if (!emu || !data) return -1;
    if (load_addr >= emu->mem_size) return -1;
    if (load_addr + size > emu->mem_size) return -1;
    memcpy(emu->memory + load_addr, data, size);
    return 0;
}

/* ---------------------------
   Register helpers (no switch/case duplicates)
   --------------------------- */

static int _is_reg64(int reg) {
    /* header may define RAX..R15 (macros) — detect by comparing against known values
       We return 1 if it's one of the R* or RIP or RFLAGS. */
    if (reg == X86_REG_RAX || reg == X86_REG_RCX || reg == X86_REG_RDX ||
        reg == X86_REG_RBX || reg == X86_REG_RSP || reg == X86_REG_RBP ||
        reg == X86_REG_RSI || reg == X86_REG_RDI || reg == X86_REG_R8  ||
        reg == X86_REG_R9  || reg == X86_REG_R10 || reg == X86_REG_R11 ||
        reg == X86_REG_R12 || reg == X86_REG_R13 || reg == X86_REG_R14 ||
        reg == X86_REG_R15 || reg == X86_REG_RIP || reg == X86_REG_RFLAGS)
        return 1;
    return 0;
}

static int _is_reg32(int reg) {
    if (reg == X86_REG_EAX || reg == X86_REG_ECX || reg == X86_REG_EDX ||
        reg == X86_REG_EBX || reg == X86_REG_ESP || reg == X86_REG_EBP ||
        reg == X86_REG_ESI || reg == X86_REG_EDI || reg == X86_REG_EIP ||
        reg == X86_REG_EFLAGS)
        return 1;
    return 0;
}

static int _is_segment(int reg) {
    if (reg == X86_REG_CS || reg == X86_REG_DS || reg == X86_REG_ES ||
        reg == X86_REG_SS || reg == X86_REG_FS || reg == X86_REG_GS) return 1;
    return 0;
}

/* ---------------------------
   Register access (use if/else to avoid duplicate-case)
   --------------------------- */
int x86_read_register(X86Emulator *emu, int reg, uint64_t *value) {
    if (!emu || !value) return -1;

    /* 64-bit registers */
    if (_is_reg64(reg)) {
        if (reg == X86_REG_RIP) { *value = emu->state.ip; return 0; }
        if (reg == X86_REG_RFLAGS) { *value = emu->state.flags; return 0; }

        /* Map RAX..R15 to gp.r[] assuming header defines RAX..R15 contiguous */
        /* We must derive index without assuming numeric order of macros; try mapping by names. */
        if (reg == X86_REG_RAX) { *value = emu->state.gp.r[0]; return 0; }
        if (reg == X86_REG_RCX) { *value = emu->state.gp.r[1]; return 0; }
        if (reg == X86_REG_RDX) { *value = emu->state.gp.r[2]; return 0; }
        if (reg == X86_REG_RBX) { *value = emu->state.gp.r[3]; return 0; }
        if (reg == X86_REG_RSP) { *value = emu->state.gp.r[4]; return 0; }
        if (reg == X86_REG_RBP) { *value = emu->state.gp.r[5]; return 0; }
        if (reg == X86_REG_RSI) { *value = emu->state.gp.r[6]; return 0; }
        if (reg == X86_REG_RDI) { *value = emu->state.gp.r[7]; return 0; }
        if (reg == X86_REG_R8)  { *value = emu->state.gp.r[8]; return 0; }
        if (reg == X86_REG_R9)  { *value = emu->state.gp.r[9]; return 0; }
        if (reg == X86_REG_R10) { *value = emu->state.gp.r[10]; return 0; }
        if (reg == X86_REG_R11) { *value = emu->state.gp.r[11]; return 0; }
        if (reg == X86_REG_R12) { *value = emu->state.gp.r[12]; return 0; }
        if (reg == X86_REG_R13) { *value = emu->state.gp.r[13]; return 0; }
        if (reg == X86_REG_R14) { *value = emu->state.gp.r[14]; return 0; }
        if (reg == X86_REG_R15) { *value = emu->state.gp.r[15]; return 0; }

        return -1;
    }

    /* 32-bit registers */
    if (_is_reg32(reg)) {
        if (reg == X86_REG_EIP) { *value = (uint64_t)(emu->state.ip & 0xFFFFFFFF); return 0; }
        if (reg == X86_REG_EFLAGS) { *value = emu->state.flags & 0xFFFFFFFF; return 0; }

        if (reg == X86_REG_EAX) { *value = emu->state.gp.e[0]; return 0; }
        if (reg == X86_REG_ECX) { *value = emu->state.gp.e[1]; return 0; }
        if (reg == X86_REG_EDX) { *value = emu->state.gp.e[2]; return 0; }
        if (reg == X86_REG_EBX) { *value = emu->state.gp.e[3]; return 0; }
        if (reg == X86_REG_ESP) { *value = emu->state.gp.e[4]; return 0; }
        if (reg == X86_REG_EBP) { *value = emu->state.gp.e[5]; return 0; }
        if (reg == X86_REG_ESI) { *value = emu->state.gp.e[6]; return 0; }
        if (reg == X86_REG_EDI) { *value = emu->state.gp.e[7]; return 0; }

        return -1;
    }

    /* segments */
    if (_is_segment(reg)) {
        if (reg == X86_REG_CS) { *value = emu->state.cs; return 0; }
        if (reg == X86_REG_DS) { *value = emu->state.ds; return 0; }
        if (reg == X86_REG_ES) { *value = emu->state.es; return 0; }
        if (reg == X86_REG_SS) { *value = emu->state.ss; return 0; }
        if (reg == X86_REG_FS) { *value = emu->state.fs; return 0; }
        if (reg == X86_REG_GS) { *value = emu->state.gs; return 0; }
    }

    return -1;
}

int x86_write_register(X86Emulator *emu, int reg, uint64_t value) {
    if (!emu) return -1;

    if (_is_reg64(reg)) {
        if (reg == X86_REG_RIP) { emu->state.ip = value; return 0; }
        if (reg == X86_REG_RFLAGS) { emu->state.flags = value; return 0; }

        if (reg == X86_REG_RAX) { emu->state.gp.r[0] = value; return 0; }
        if (reg == X86_REG_RCX) { emu->state.gp.r[1] = value; return 0; }
        if (reg == X86_REG_RDX) { emu->state.gp.r[2] = value; return 0; }
        if (reg == X86_REG_RBX) { emu->state.gp.r[3] = value; return 0; }
        if (reg == X86_REG_RSP) { emu->state.gp.r[4] = value; return 0; }
        if (reg == X86_REG_RBP) { emu->state.gp.r[5] = value; return 0; }
        if (reg == X86_REG_RSI) { emu->state.gp.r[6] = value; return 0; }
        if (reg == X86_REG_RDI) { emu->state.gp.r[7] = value; return 0; }
        if (reg == X86_REG_R8)  { emu->state.gp.r[8] = value; return 0; }
        if (reg == X86_REG_R9)  { emu->state.gp.r[9] = value; return 0; }
        if (reg == X86_REG_R10) { emu->state.gp.r[10] = value; return 0; }
        if (reg == X86_REG_R11) { emu->state.gp.r[11] = value; return 0; }
        if (reg == X86_REG_R12) { emu->state.gp.r[12] = value; return 0; }
        if (reg == X86_REG_R13) { emu->state.gp.r[13] = value; return 0; }
        if (reg == X86_REG_R14) { emu->state.gp.r[14] = value; return 0; }
        if (reg == X86_REG_R15) { emu->state.gp.r[15] = value; return 0; }
        return -1;
    }

    if (_is_reg32(reg)) {
        if (reg == X86_REG_EIP) { emu->state.ip = (emu->state.ip & ~0xFFFFFFFFULL) | (value & 0xFFFFFFFFULL); return 0; }
        if (reg == X86_REG_EFLAGS) { emu->state.flags = (emu->state.flags & ~0xFFFFFFFFULL) | (value & 0xFFFFFFFFULL); return 0; }

        if (reg == X86_REG_EAX) { emu->state.gp.e[0] = (uint32_t)value; return 0; }
        if (reg == X86_REG_ECX) { emu->state.gp.e[1] = (uint32_t)value; return 0; }
        if (reg == X86_REG_EDX) { emu->state.gp.e[2] = (uint32_t)value; return 0; }
        if (reg == X86_REG_EBX) { emu->state.gp.e[3] = (uint32_t)value; return 0; }
        if (reg == X86_REG_ESP) { emu->state.gp.e[4] = (uint32_t)value; return 0; }
        if (reg == X86_REG_EBP) { emu->state.gp.e[5] = (uint32_t)value; return 0; }
        if (reg == X86_REG_ESI) { emu->state.gp.e[6] = (uint32_t)value; return 0; }
        if (reg == X86_REG_EDI) { emu->state.gp.e[7] = (uint32_t)value; return 0; }
        return -1;
    }

    if (_is_segment(reg)) {
        if (reg == X86_REG_CS) { emu->state.cs = (uint16_t)(value & 0xFFFF); return 0; }
        if (reg == X86_REG_DS) { emu->state.ds = (uint16_t)(value & 0xFFFF); return 0; }
        if (reg == X86_REG_ES) { emu->state.es = (uint16_t)(value & 0xFFFF); return 0; }
        if (reg == X86_REG_SS) { emu->state.ss = (uint16_t)(value & 0xFFFF); return 0; }
        if (reg == X86_REG_FS) { emu->state.fs = (uint16_t)(value & 0xFFFF); return 0; }
        if (reg == X86_REG_GS) { emu->state.gs = (uint16_t)(value & 0xFFFF); return 0; }
    }

    return -1;
}

/* ---------------------------
   Memory read/write
   --------------------------- */
int x86_read_memory(X86Emulator *emu, uint64_t addr, void *buffer, size_t size) {
    if (!emu || !buffer) return -1;
    if (addr + size > emu->mem_size) return -1;
    memcpy(buffer, emu->memory + addr, size);
    return 0;
}

int x86_write_memory(X86Emulator *emu, uint64_t addr, const void *buffer, size_t size) {
    if (!emu || !buffer) return -1;
    if (addr + size > emu->mem_size) return -1;
    memcpy(emu->memory + addr, buffer, size);
    return 0;
}

/* ---------------------------
   I/O ports
   --------------------------- */
int x86_read_port(X86Emulator *emu, uint16_t port, uint8_t *value, size_t size) {
    if (!emu || !value) return -1;
    if ((uint32_t)port + size > 65536) return -1;
    memcpy(value, emu->io_ports + port, size);
    return 0;
}

int x86_write_port(X86Emulator *emu, uint16_t port, const uint8_t *value, size_t size) {
    if (!emu || !value) return -1;
    if ((uint32_t)port + size > 65536) return -1;
    memcpy(emu->io_ports + port, value, size);
    return 0;
}

/* ---------------------------
   Execution (step/run)
   --------------------------- */
int x86_step(X86Emulator *emu, size_t *instr_executed) {
    if (!emu) return -1;

    if (emu->ube) {
        /* prefer top-level engine stepping if attached */
        ube_error_t err = ube_step(emu->ube, instr_executed);
        if (err == UBE_ERR_OK) {
            emu->total_instructions += (instr_executed ? *instr_executed : 1);
            return 0;
        }
        /* fallback if engine step fails */
    }

    /* naive fallback: increment IP by 1 (best-effort) */
    emu->state.ip += 1;
    if (instr_executed) *instr_executed = 1;
    emu->total_instructions += 1;
    return 0;
}

int x86_execute(X86Emulator *emu, uint64_t start_addr, uint64_t end_addr, size_t max_instructions, size_t *instr_executed) {
    if (!emu) return -1;
    emu->running = true;
    emu->state.breakpoint_hit = false;

    size_t count = 0;
    if (emu->ube) {
        ube_error_t err = ube_run(emu->ube, start_addr, end_addr, &count, 0);
        if (err == UBE_ERR_OK) {
            if (instr_executed) *instr_executed = count;
            emu->total_instructions += count;
            return 0;
        }
        return -1;
    }

    /* fallback simple loop */
    while (emu->running && count < max_instructions) {
        size_t stepped = 0;
        if (x86_step(emu, &stepped) != 0) break;
        count += stepped;
        if (end_addr != 0 && emu->state.ip == end_addr) break;
    }

    if (instr_executed) *instr_executed = count;
    emu->total_instructions += count;
    return 0;
}

/* ---------------------------
   State management & control
   --------------------------- */
int x86_save_state(X86Emulator *emu, X86State *state) {
    if (!emu || !state) return -1;
    memcpy(state, &emu->state, sizeof(X86State));
    return 0;
}

int x86_restore_state(X86Emulator *emu, const X86State *state) {
    if (!emu || !state) return -1;
    memcpy(&emu->state, state, sizeof(X86State));
    return 0;
}

int x86_reset(X86Emulator *emu) {
    if (!emu) return -1;
    memset(&emu->state, 0, sizeof(X86State));
    uint64_t sp = emu->mem_size - 0x1000;
    if (emu->mode == 64) emu->state.gp.r[X86_REG_RSP] = sp;
    else emu->state.gp.e[X86_REG_ESP] = (uint32_t)sp;
    emu->running = false;
    emu->total_instructions = 0;
    return 0;
}

int x86_set_breakpoint(X86Emulator *emu, uint64_t addr) {
    if (!emu) return -1;
    emu->state.breakpoint_hit = true;
    emu->state.breakpoint_addr = addr;
    return 0;
}

int x86_clear_breakpoint(X86Emulator *emu, uint64_t addr) {
    (void)addr;
    if (!emu) return -1;
    emu->state.breakpoint_hit = false;
    emu->state.breakpoint_addr = 0;
    return 0;
}

int x86_switch_to_real_mode(X86Emulator *emu) {
    if (!emu) return -1;
    emu->mode = 16;
    emu->state.real_mode = true;
    emu->state.protected_mode = false;
    emu->state.long_mode = false;
    return 0;
}

int x86_switch_to_protected_mode(X86Emulator *emu) {
    if (!emu) return -1;
    emu->mode = 32;
    emu->state.protected_mode = true;
    emu->state.real_mode = false;
    emu->state.long_mode = false;
    return 0;
}

int x86_switch_to_long_mode(X86Emulator *emu) {
    if (!emu) return -1;
    emu->mode = 64;
    emu->state.long_mode = true;
    emu->state.protected_mode = false;
    emu->state.real_mode = false;
    return 0;
}

/* ---------------------------
   Interrupts & I/O handler registration
   --------------------------- */
int x86_trigger_interrupt(X86Emulator *emu, uint8_t vector) {
    if (!emu) return -1;
    if (emu->interrupt_handler) emu->interrupt_handler(emu->interrupt_user, vector);
    return 0;
}

int x86_set_interrupt_handler(X86Emulator *emu, void (*handler)(void *user, int vector), void *user) {
    if (!emu) return -1;
    emu->interrupt_handler = handler;
    emu->interrupt_user = user;
    return 0;
}

/* ---------------------------
   Debug / Trace / Perf
   --------------------------- */
int x86_disassemble(X86Emulator *emu, uint64_t addr, size_t count, char **output) {
    (void)emu; (void)addr; (void)count; (void)output;
    /* prefer top-level Capstone usage; stub here */
    return -1;
}

int x86_trace_enable(X86Emulator *emu, bool enable) {
    if (!emu) return -1;
    emu->tracing = enable;
    return 0;
}

int x86_get_perf_stats(X86Emulator *emu, uint64_t *cycles, uint64_t *instructions, uint64_t *branches) {
    if (!emu) return -1;
    if (cycles) *cycles = emu->total_cycles;
    if (instructions) *instructions = emu->total_instructions;
    if (branches) *branches = emu->total_branches;
    return 0;
}

/* ---------------------------
   Architecture detection helpers
   --------------------------- */
uint64_t x86_16_detect_entry(const uint8_t *data, size_t size) {
    (void)size;
    if (!data) return 0;
    /* default for flat 16-bit binaries */
    return 0x0000;
}

uint64_t x86_32_detect_entry(const uint8_t *data, size_t size) {
    if (!data) return 0;
    if (size >= sizeof(Elf32_Ehdr)) {
        const Elf32_Ehdr *ehdr = (const Elf32_Ehdr *)data;
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0) return ehdr->e_entry;
    }
    for (size_t i = 0; i + 2 < size; ++i) {
        if (data[i] == 0x55 && data[i+1] == 0x89 && data[i+2] == 0xE5) return i;
    }
    return 0;
}

uint64_t x86_64_detect_entry(const uint8_t *data, size_t size) {
    if (!data) return 0;
    if (size >= sizeof(Elf64_Ehdr)) {
        const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)data;
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0) return ehdr->e_entry;
    }
    for (size_t i = 0; i + 3 < size; ++i) {
        if (data[i] == 0x55 && data[i+1] == 0x48 && data[i+2] == 0x89 && data[i+3] == 0xE5) return i;
    }
    return 0;
}

/* ---------------------------
   Baremetal execution helper
   --------------------------- */
int x86_execute_baremetal(const uint8_t *code, size_t size, uint64_t entry, int mode, size_t mem_size, bool verbose, uint64_t *result) {
    if (!code || size == 0) return -1;

    if (mode == 0) {
        if (is_x86_64_code(code, size)) mode = 64;
        else if (is_x86_32_code(code, size)) mode = 32;
        else mode = 16;
    }

    X86Emulator *emu = x86_create_emulator(mode, mem_size ? mem_size : (2 * 1024 * 1024));
    if (!emu) return -1;

    uint64_t load_addr = (mode == 16) ? 0x0000 : 0x100000;
    if (load_addr + size > emu->mem_size) {
        if (size <= emu->mem_size) load_addr = 0;
        else { x86_destroy_emulator(emu); return -1; }
    }

    if (x86_load_binary(emu, code, size, load_addr) < 0) { x86_destroy_emulator(emu); return -1; }

    uint64_t pc = load_addr + entry;
    uint64_t sp = load_addr + emu->mem_size - 0x1000;

    if (mode == 64) {
        x86_write_register(emu, X86_REG_RSP, sp);
        x86_write_register(emu, X86_REG_RIP, pc);
    } else if (mode == 32) {
        x86_write_register(emu, X86_REG_ESP, (uint32_t)sp);
        x86_write_register(emu, X86_REG_EIP, (uint32_t)pc);
    } else {
        x86_write_register(emu, X86_REG_ESP, (uint16_t)sp);
        x86_write_register(emu, X86_REG_EIP, (uint16_t)pc);
    }

    if (verbose) {
        printf("x86 Baremetal Execution: mode=%d load=0x%lx entry=0x%lx sp=0x%lx mem=%zu\n",
               mode, (unsigned long)load_addr, (unsigned long)pc, (unsigned long)sp, emu->mem_size);
    }

    size_t instr_executed = 0;
    int ret = x86_execute(emu, pc, 0, 1000000, &instr_executed);

    if (verbose) {
        printf("  Instructions executed: %zu\n", instr_executed);
        printf("  Return: %d\n", ret);
    }

    if (result) {
        uint64_t r = 0;
        if (mode == 64) x86_read_register(emu, X86_REG_RAX, &r);
        else x86_read_register(emu, X86_REG_EAX, &r);
        *result = r;
    }

    x86_destroy_emulator(emu);
    return ret;
}

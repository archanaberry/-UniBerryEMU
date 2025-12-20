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

#include "arch/8086.h"
#include "../ubemu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <assert.h>

// ==============================
// Internal x86 Emulator Structure
// ==============================
struct X86Emulator {
    UBEContext *ube;
    int mode;  // 16, 32, or 64
    X86State state;
    
    // Callbacks
    void (*interrupt_handler)(void *user, int vector);
    void *interrupt_user;
    
    // Execution state
    bool running;
    bool tracing;
    
    // Memory
    size_t mem_size;
    uint8_t *memory;
    
    // I/O Ports
    uint8_t *io_ports;
    
    // Statistics
    uint64_t total_cycles;
    uint64_t total_instructions;
    uint64_t total_branches;
};

// ==============================
// Helper Functions
// ==============================
static bool is_x86_64_code(const uint8_t *data, size_t size) {
    // Check for x86-64 specific instructions or ELF64
    if (size >= 4) {
        // Check for REX prefix (0x40-0x4F)
        for (size_t i = 0; i < size - 4; i++) {
            if ((data[i] & 0xF0) == 0x40) { // REX prefix
                return true;
            }
        }
    }
    
    // Check ELF header
    if (size >= sizeof(Elf64_Ehdr)) {
        const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)data;
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0 && 
            ehdr->e_ident[EI_CLASS] == ELFCLASS64) {
            return true;
        }
    }
    
    return false;
}

static bool is_x86_32_code(const uint8_t *data, size_t size) {
    // Check for 32-bit specific instructions or ELF32
    if (size >= 4) {
        // Check for 32-bit opcodes
        for (size_t i = 0; i < size - 2; i++) {
            if (data[i] == 0xCD && data[i+1] == 0x80) { // int 0x80
                return true;
            }
        }
    }
    
    // Check ELF header
    if (size >= sizeof(Elf32_Ehdr)) {
        const Elf32_Ehdr *ehdr = (const Elf32_Ehdr *)data;
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0 && 
            ehdr->e_ident[EI_CLASS] == ELFCLASS32) {
            return true;
        }
    }
    
    return false;
}

// ==============================
// Creation & Destruction
// ==============================
X86Emulator* x86_create_emulator(int mode, size_t mem_size) {
    X86Emulator *emu = calloc(1, sizeof(X86Emulator));
    if (!emu) return NULL;
    
    emu->mode = mode;
    emu->mem_size = mem_size;
    
    // Create UBE context
    ube_arch_t arch;
    ube_mode_t ube_mode = 0;
    
    switch (mode) {
        case 16:
            arch = UBE_ARCH_X86_16;
            ube_mode = UBE_MODE_REAL;
            emu->state.real_mode = true;
            break;
        case 32:
            arch = UBE_ARCH_X86_32;
            ube_mode = UBE_MODE_PROTECTED;
            emu->state.protected_mode = true;
            break;
        case 64:
            arch = UBE_ARCH_X86_64;
            ube_mode = UBE_MODE_LONG;
            emu->state.long_mode = true;
            break;
        default:
            free(emu);
            return NULL;
    }
    
    emu->ube = ube_create_context(arch, ube_mode, mem_size);
    if (!emu->ube) {
        free(emu);
        return NULL;
    }
    
    // Allocate memory
    emu->memory = calloc(1, mem_size);
    if (!emu->memory) {
        ube_destroy_context(emu->ube);
        free(emu);
        return NULL;
    }
    
    // Allocate I/O ports (64KB)
    emu->io_ports = calloc(1, 65536);
    if (!emu->io_ports) {
        free(emu->memory);
        ube_destroy_context(emu->ube);
        free(emu);
        return NULL;
    }
    
    // Map memory
    uint64_t base_addr = (mode == 16) ? 0x0000 : 0x00000000;
    ube_map_memory(emu->ube, base_addr, mem_size, true, true, true);
    
    // Initialize state
    memset(&emu->state, 0, sizeof(X86State));
    
    // Setup segment registers
    emu->state.cs = 0x0000;
    emu->state.ds = 0x0000;
    emu->state.es = 0x0000;
    emu->state.ss = 0x0000;
    emu->state.fs = 0x0000;
    emu->state.gs = 0x0000;
    
    // Setup stack pointer
    uint64_t sp = base_addr + mem_size - 0x1000;
    if (mode == 64) {
        emu->state.gp.r[X86_REG_RSP] = sp;
    } else if (mode == 32) {
        emu->state.gp.e[X86_REG_ESP] = (uint32_t)sp;
    } else {
        emu->state.gp.e[X86_REG_ESP] = (uint32_t)sp & 0xFFFF;
    }
    
    return emu;
}

void x86_destroy_emulator(X86Emulator *emu) {
    if (!emu) return;
    
    if (emu->ube) ube_destroy_context(emu->ube);
    if (emu->memory) free(emu->memory);
    if (emu->io_ports) free(emu->io_ports);
    free(emu);
}

// ==============================
// Memory Management
// ==============================
int x86_map_memory(X86Emulator *emu, uint64_t addr, size_t size, 
                  bool read, bool write, bool exec) {
    if (!emu || !emu->ube) return -1;
    
    ube_error_t err = ube_map_memory(emu->ube, addr, size, read, write, exec);
    return (err == UBE_ERR_OK) ? 0 : -1;
}

int x86_load_binary(X86Emulator *emu, const uint8_t *data, size_t size, 
                   uint64_t load_addr) {
    if (!emu || !emu->ube || !data) return -1;
    
    ube_error_t err = ube_load_binary(emu->ube, data, size, load_addr);
    if (err == UBE_ERR_OK) {
        // Also copy to our local memory
        if (load_addr < emu->mem_size && load_addr + size <= emu->mem_size) {
            memcpy(emu->memory + load_addr, data, size);
        }
    }
    
    return (err == UBE_ERR_OK) ? 0 : -1;
}

// ==============================
// Register Access
// ==============================
int x86_read_register(X86Emulator *emu, int reg, uint64_t *value) {
    if (!emu || !emu->ube || !value) return -1;
    
    ube_error_t err = ube_read_register(emu->ube, reg, value);
    return (err == UBE_ERR_OK) ? 0 : -1;
}

int x86_write_register(X86Emulator *emu, int reg, uint64_t value) {
    if (!emu || !emu->ube) return -1;
    
    ube_error_t err = ube_write_register(emu->ube, reg, value);
    return (err == UBE_ERR_OK) ? 0 : -1;
}

// ==============================
// Execution
// ==============================
int x86_execute(X86Emulator *emu, uint64_t start_addr, uint64_t end_addr,
               size_t max_instructions, size_t *instr_executed) {
    if (!emu || !emu->ube) return -1;
    
    emu->running = true;
    emu->state.breakpoint_hit = false;
    
    size_t count = 0;
    ube_error_t err;
    
    if (end_addr == 0) {
        // Run until breakpoint or exception
        while (emu->running && count < max_instructions && 
               !emu->state.breakpoint_hit) {
            err = ube_step(emu->ube, NULL);
            if (err != UBE_ERR_OK) break;
            count++;
        }
    } else {
        // Run to specific address
        err = ube_run(emu->ube, start_addr, end_addr, &count, 0);
    }
    
    if (instr_executed) *instr_executed = count;
    emu->total_instructions += count;
    
    return (err == UBE_ERR_OK) ? 0 : -1;
}

// ==============================
// Architecture Detection
// ==============================
uint64_t x86_16_detect_entry(const uint8_t *data, size_t size) {
    // For 16-bit binaries, entry is usually at 0x0000
    if (size >= 0x10) {
        // Check for COM file signature or simple binary
        // COM files start at 0x100, but flat binaries at 0x0
        return 0x0000;
    }
    return 0;
}

uint64_t x86_32_detect_entry(const uint8_t *data, size_t size) {
    // Check for ELF32
    if (size >= sizeof(Elf32_Ehdr)) {
        const Elf32_Ehdr *ehdr = (const Elf32_Ehdr *)data;
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0) {
            return ehdr->e_entry;
        }
    }
    
    // For flat binaries, try to find code start
    // Look for common x86 prologues
    for (size_t i = 0; i + 5 < size; i++) {
        // push ebp; mov ebp, esp
        if (data[i] == 0x55 && data[i+1] == 0x89 && data[i+2] == 0xE5) {
            return i;
        }
    }
    
    return 0;
}

uint64_t x86_64_detect_entry(const uint8_t *data, size_t size) {
    // Check for ELF64
    if (size >= sizeof(Elf64_Ehdr)) {
        const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)data;
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0) {
            return ehdr->e_entry;
        }
    }
    
    // For flat binaries, try to find code start
    for (size_t i = 0; i + 5 < size; i++) {
        // push rbp; mov rbp, rsp (x86-64 prologue)
        if (data[i] == 0x55 && data[i+1] == 0x48 && data[i+2] == 0x89 &&
            data[i+3] == 0xE5) {
            return i;
        }
    }
    
    return 0;
}

// ==============================
// Baremetal Execution
// ==============================
int x86_execute_baremetal(const uint8_t *code, size_t size, uint64_t entry,
                         int mode, size_t mem_size, bool verbose, uint64_t *result) {
    if (!code || size == 0) return -1;
    
    // Auto-detect mode if not specified
    if (mode == 0) {
        if (is_x86_64_code(code, size)) {
            mode = 64;
        } else if (is_x86_32_code(code, size)) {
            mode = 32;
        } else {
            mode = 16; // Default to 16-bit
        }
    }
    
    // Create emulator
    X86Emulator *emu = x86_create_emulator(mode, mem_size);
    if (!emu) return -1;
    
    // Load code
    uint64_t load_addr = (mode == 16) ? 0x0000 : 0x100000;
    if (x86_load_binary(emu, code, size, load_addr) < 0) {
        x86_destroy_emulator(emu);
        return -1;
    }
    
    // Setup registers
    uint64_t pc = load_addr + entry;
    uint64_t sp = load_addr + mem_size - 0x1000;
    
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
        printf("x86 Baremetal Execution:\n");
        printf("  Mode: %d-bit\n", mode);
        printf("  Load Address: 0x%lx\n", load_addr);
        printf("  Entry Point: 0x%lx\n", pc);
        printf("  Stack Pointer: 0x%lx\n", sp);
        printf("  Memory Size: %zu MB\n", mem_size / (1024*1024));
    }
    
    // Execute
    size_t instr_executed = 0;
    int ret = x86_execute(emu, pc, 0, 1000000, &instr_executed);
    
    if (verbose) {
        printf("  Instructions Executed: %zu\n", instr_executed);
        printf("  Execution %s\n", ret == 0 ? "SUCCESS" : "FAILED");
    }
    
    // Get result from EAX/RAX
    if (result) {
        if (mode == 64) {
            x86_read_register(emu, X86_REG_RAX, result);
        } else {
            uint64_t eax;
            x86_read_register(emu, X86_REG_EAX, &eax);
            *result = eax;
        }
    }
    
    x86_destroy_emulator(emu);
    return ret;
}
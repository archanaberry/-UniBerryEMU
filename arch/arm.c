/****************************************************************/
//                                                              //
//  -------------------UniBerry EMU Engine-------------------   //
//  Created by: Archana Berry                                   //
//  Architecture: ARM (AArch32/AArch64)                         //
//  Version resource: v0.001_alpha                              //
//  File: arch/arm.c                                            //
//  Type: source[architecture]                                  //
//  Desc: ARM architecture support for baremetal emulation      //
//                                                              //
//  ----------------------------------------------------------  //
//                                                              //
//  ---- Supports ARMv7 (AArch32) and ARMv8 (AArch64)      ---- //
//  ---- baremetal execution, including Thumb mode and     ---- //
//  ---- system register emulation for kernel testing.     ---- //
//                                                              //
/****************************************************************/
//                                                              //
//  Patiently awaiting the release of UniBerryEMU               //
//                                                              //
/****************************************************************/

// arm.c

#include "arm.h"
#include "../ubemu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <assert.h>

// ==============================
// Internal ARM Emulator Structure
// ==============================
struct ARMEmulator {
    UBEContext *ube;
    bool is_64bit;
    bool thumb_mode;
    ARMState state;
    
    // Callbacks
    void (*interrupt_handler)(void *user, int type);
    void *interrupt_user;
    
    // Execution state
    bool running;
    bool tracing;
    
    // Memory
    size_t mem_size;
    uint8_t *memory;
    
    // Statistics
    uint64_t total_cycles;
    uint64_t total_instructions;
};

// ==============================
// Helper Functions
// ==============================
static uint64_t arm_read_uint32(const uint8_t *data, bool big_endian) {
    if (big_endian) {
        return (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    } else {
        return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
    }
}

static uint64_t arm_read_uint64(const uint8_t *data, bool big_endian) {
    uint32_t low, high;
    if (big_endian) {
        high = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
        low = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    } else {
        low = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
        high = data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24);
    }
    return ((uint64_t)high << 32) | low;
}

// ==============================
// Creation & Destruction
// ==============================
ARMEmulator* arm_create_emulator(bool is_64bit, bool thumb_mode, size_t mem_size) {
    ARMEmulator *emu = calloc(1, sizeof(ARMEmulator));
    if (!emu) return NULL;
    
    emu->is_64bit = is_64bit;
    emu->thumb_mode = thumb_mode;
    emu->mem_size = mem_size;
    
    // Create UBE context
    ube_arch_t arch = is_64bit ? UBE_ARCH_ARM64 : UBE_ARCH_ARM32;
    ube_mode_t mode = thumb_mode ? UBE_MODE_THUMB : UBE_MODE_ARM;
    
    emu->ube = ube_create_context(arch, mode, mem_size);
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
    
    // Map memory
    ube_map_memory(emu->ube, 0x00000000, mem_size, true, true, true);
    
    // Initialize state
    memset(&emu->state, 0, sizeof(ARMState));
    emu->state.thumb_mode = thumb_mode;
    emu->state.privileged = true;
    
    if (is_64bit) {
        // Initialize ARM64 registers
        emu->state.x[ARM64_REG_SP] = 0x80000000 + mem_size - 0x1000;
        emu->state.current_el = 1; // EL1
    } else {
        // Initialize ARM32 registers
        emu->state.r[ARM_REG_SP] = 0x80000000 + mem_size - 0x1000;
    }
    
    return emu;
}

void arm_destroy_emulator(ARMEmulator *emu) {
    if (!emu) return;
    
    if (emu->ube) ube_destroy_context(emu->ube);
    if (emu->memory) free(emu->memory);
    free(emu);
}

// ==============================
// Memory Management
// ==============================
int arm_map_memory(ARMEmulator *emu, uint64_t addr, size_t size, 
                  bool read, bool write, bool exec) {
    if (!emu || !emu->ube) return -1;
    
    ube_error_t err = ube_map_memory(emu->ube, addr, size, read, write, exec);
    return (err == UBE_ERR_OK) ? 0 : -1;
}

int arm_load_binary(ARMEmulator *emu, const uint8_t *data, size_t size, 
                   uint64_t load_addr) {
    if (!emu || !emu->ube || !data) return -1;
    
    ube_error_t err = ube_load_binary(emu->ube, data, size, load_addr);
    if (err == UBE_ERR_OK) {
        // Also copy to our local memory for faster access
        if (load_addr < emu->mem_size && load_addr + size <= emu->mem_size) {
            memcpy(emu->memory + load_addr, data, size);
        }
    }
    
    return (err == UBE_ERR_OK) ? 0 : -1;
}

// ==============================
// Register Access
// ==============================
int arm_read_register(ARMEmulator *emu, int reg, uint64_t *value) {
    if (!emu || !emu->ube || !value) return -1;
    
    ube_error_t err = ube_read_register(emu->ube, reg, value);
    return (err == UBE_ERR_OK) ? 0 : -1;
}

int arm_write_register(ARMEmulator *emu, int reg, uint64_t value) {
    if (!emu || !emu->ube) return -1;
    
    ube_error_t err = ube_write_register(emu->ube, reg, value);
    return (err == UBE_ERR_OK) ? 0 : -1;
}

// ==============================
// Execution
// ==============================
int arm_execute(ARMEmulator *emu, uint64_t start_addr, uint64_t end_addr,
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
uint64_t aarch32_detect_entry(const uint8_t *data, size_t size) {
    // Check for ELF header
    if (size >= sizeof(Elf32_Ehdr)) {
        const Elf32_Ehdr *ehdr = (const Elf32_Ehdr *)data;
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0) {
            return ehdr->e_entry;
        }
    }
    
    // Check for ARM vector table (usually at 0x0 or 0xFFFF0000)
    if (size >= 0x20) {
        // Check for valid vector table entries (branches)
        for (int i = 0; i < 8; i++) {
            uint32_t vector = arm_read_uint32(data + i * 4, false);
            // Check if it's a branch instruction
            if ((vector & 0xFF000000) == 0xEA000000 ||  // B
                (vector & 0xFF000000) == 0xEB000000) {  // BL
                return i * 4;
            }
        }
    }
    
    return 0;
}

uint64_t aarch64_detect_entry(const uint8_t *data, size_t size) {
    // Check for ELF64 header
    if (size >= sizeof(Elf64_Ehdr)) {
        const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)data;
        if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0) {
            return ehdr->e_entry;
        }
    }
    
    // ARM64 doesn't have a fixed vector table like ARM32
    // Return 0 for flat binaries
    return 0;
}

// ==============================
// Baremetal Execution
// ==============================
int arm_execute_baremetal(const uint8_t *code, size_t size, uint64_t entry,
                         size_t mem_size, bool verbose, uint64_t *result) {
    if (!code || size == 0) return -1;
    
    // Create emulator
    bool is_64bit = (size > 4 && arm_read_uint32(code, false) == 0x14000000);
    ARMEmulator *emu = arm_create_emulator(is_64bit, false, mem_size);
    if (!emu) return -1;
    
    // Load code at 0x80000000 (typical baremetal load address)
    uint64_t load_addr = 0x80000000;
    if (arm_load_binary(emu, code, size, load_addr) < 0) {
        arm_destroy_emulator(emu);
        return -1;
    }
    
    // Setup stack pointer
    uint64_t sp = load_addr + mem_size - 0x1000;
    if (is_64bit) {
        arm_write_register(emu, ARM64_REG_SP, sp);
    } else {
        arm_write_register(emu, ARM_REG_SP, sp);
    }
    
    // Setup entry point
    uint64_t pc = load_addr + entry;
    if (is_64bit) {
        arm_write_register(emu, ARM64_REG_PC, pc);
    } else {
        arm_write_register(emu, ARM_REG_PC, pc);
    }
    
    if (verbose) {
        printf("ARM Baremetal Execution:\n");
        printf("  Architecture: %s\n", is_64bit ? "ARM64" : "ARM32");
        printf("  Load Address: 0x%lx\n", load_addr);
        printf("  Entry Point: 0x%lx\n", pc);
        printf("  Stack Pointer: 0x%lx\n", sp);
        printf("  Memory Size: %zu MB\n", mem_size / (1024*1024));
    }
    
    // Execute
    size_t instr_executed = 0;
    int ret = arm_execute(emu, pc, 0, 1000000, &instr_executed);
    
    if (verbose) {
        printf("  Instructions Executed: %zu\n", instr_executed);
        printf("  Execution %s\n", ret == 0 ? "SUCCESS" : "FAILED");
    }
    
    // Get result from X0/R0
    if (result) {
        if (is_64bit) {
            arm_read_register(emu, ARM64_REG_X0, result);
        } else {
            uint64_t r0;
            arm_read_register(emu, ARM_REG_R0, &r0);
            *result = r0;
        }
    }
    
    arm_destroy_emulator(emu);
    return ret;
}
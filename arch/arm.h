/****************************************************************/
//                                                              //
//  -------------------UniBerry EMU Engine-------------------   //
//  Created by: Archana Berry                                   //
//  Architecture: ARM (AArch32/AArch64)                         //
//  Version resource: v0.001_alpha                              //
//  File: arch/arm.h                                            //
//  Type: header[architecture]                                  //
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

// arm.h

#ifndef ARCH_ARM_H
#define ARCH_ARM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ==============================
// ARM Constants
// ==============================
#define ARM_REG_R0   0
#define ARM_REG_R1   1
#define ARM_REG_R2   2
#define ARM_REG_R3   3
#define ARM_REG_R4   4
#define ARM_REG_R5   5
#define ARM_REG_R6   6
#define ARM_REG_R7   7
#define ARM_REG_R8   8
#define ARM_REG_R9   9
#define ARM_REG_R10  10
#define ARM_REG_R11  11
#define ARM_REG_R12  12
#define ARM_REG_SP   13
#define ARM_REG_LR   14
#define ARM_REG_PC   15
#define ARM_REG_CPSR 16

#define ARM64_REG_X0   0
#define ARM64_REG_X1   1
#define ARM64_REG_X2   2
#define ARM64_REG_X3   3
#define ARM64_REG_X4   4
#define ARM64_REG_X5   5
#define ARM64_REG_X6   6
#define ARM64_REG_X7   7
#define ARM64_REG_X8   8
#define ARM64_REG_X9   9
#define ARM64_REG_X10  10
#define ARM64_REG_X11  11
#define ARM64_REG_X12  12
#define ARM64_REG_X13  13
#define ARM64_REG_X14  14
#define ARM64_REG_X15  15
#define ARM64_REG_X16  16
#define ARM64_REG_X17  17
#define ARM64_REG_X18  18
#define ARM64_REG_X19  19
#define ARM64_REG_X20  20
#define ARM64_REG_X21  21
#define ARM64_REG_X22  22
#define ARM64_REG_X23  23
#define ARM64_REG_X24  24
#define ARM64_REG_X25  25
#define ARM64_REG_X26  26
#define ARM64_REG_X27  27
#define ARM64_REG_X28  28
#define ARM64_REG_X29  29
#define ARM64_REG_X30  30
#define ARM64_REG_SP   31
#define ARM64_REG_PC   32
#define ARM64_REG_PSTATE 33

// ==============================
// ARM Context Structure
// ==============================
typedef struct {
    // General Purpose Registers
    union {
        uint32_t r[16];  // ARM32
        uint64_t x[31];  // ARM64
    };
    
    // Special Registers
    uint32_t cpsr;      // ARM32 CPSR
    uint64_t pstate;    // ARM64 PSTATE
    
    // System Registers
    uint32_t ttbr0;     // Translation Table Base Register 0
    uint32_t ttbr1;     // Translation Table Base Register 1
    uint32_t ttbcr;     // Translation Table Base Control Register
    uint32_t dacr;      // Domain Access Control Register
    
    // Floating Point/NEON
    union {
        uint64_t d[32];  // Double precision
        uint32_t s[32];  // Single precision
        uint16_t h[32];  // Half precision
        uint8_t  b[64];  // Byte
    } neon;
    
    // Execution State
    bool thumb_mode;
    bool big_endian;
    bool privileged;
    uint8_t current_el;  // Exception Level (ARM64)
    
    // Memory Management
    uint64_t page_table_base;
    uint32_t mmu_enabled;
    
    // Cache State
    uint32_t cache_type;
    uint32_t cache_size;
    
    // Performance Counters
    uint64_t cycle_count;
    uint64_t instr_count;
    
    // Interrupt State
    uint32_t irq_mask;
    uint32_t fiq_mask;
    bool irq_pending;
    bool fiq_pending;
    
    // Debug State
    uint32_t debug_registers[16];
    bool breakpoint_hit;
    uint64_t breakpoint_addr;
} ARMState;

// ==============================
// ARM Emulation Functions
// ==============================
typedef struct ARMEmulator ARMEmulator;

// Creation & Destruction
ARMEmulator* arm_create_emulator(bool is_64bit, bool thumb_mode, size_t mem_size);
void arm_destroy_emulator(ARMEmulator *emu);

// Memory Management
int arm_map_memory(ARMEmulator *emu, uint64_t addr, size_t size, 
                  bool read, bool write, bool exec);
int arm_load_binary(ARMEmulator *emu, const uint8_t *data, size_t size, 
                   uint64_t load_addr);

// Register Access
int arm_read_register(ARMEmulator *emu, int reg, uint64_t *value);
int arm_write_register(ARMEmulator *emu, int reg, uint64_t value);
int arm_read_memory(ARMEmulator *emu, uint64_t addr, void *buffer, size_t size);
int arm_write_memory(ARMEmulator *emu, uint64_t addr, const void *buffer, size_t size);

// Execution
int arm_execute(ARMEmulator *emu, uint64_t start_addr, uint64_t end_addr,
               size_t max_instructions, size_t *instr_executed);
int arm_step(ARMEmulator *emu, size_t *instr_executed);

// State Management
int arm_save_state(ARMEmulator *emu, ARMState *state);
int arm_restore_state(ARMEmulator *emu, const ARMState *state);

// System Control
int arm_reset(ARMEmulator *emu);
int arm_set_breakpoint(ARMEmulator *emu, uint64_t addr);
int arm_clear_breakpoint(ARMEmulator *emu, uint64_t addr);

// Interrupt Handling
int arm_trigger_irq(ARMEmulator *emu);
int arm_trigger_fiq(ARMEmulator *emu);
int arm_set_interrupt_handler(ARMEmulator *emu, 
                             void (*handler)(void *user, int type),
                             void *user);

// Debug & Trace
int arm_disassemble(ARMEmulator *emu, uint64_t addr, size_t count, 
                   char **output);
int arm_trace_enable(ARMEmulator *emu, bool enable);
int arm_get_perf_stats(ARMEmulator *emu, uint64_t *cycles, 
                      uint64_t *instructions);

// ==============================
// Architecture Detection
// ==============================
uint64_t aarch32_detect_entry(const uint8_t *data, size_t size);
uint64_t aarch64_detect_entry(const uint8_t *data, size_t size);

// ==============================
// Baremetal Execution
// ==============================
int arm_execute_baremetal(const uint8_t *code, size_t size, uint64_t entry,
                         size_t mem_size, bool verbose, uint64_t *result);

#ifdef __cplusplus
}
#endif

#endif /* ARCH_ARM_H */
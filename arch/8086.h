/****************************************************************/
//                                                              //
//  -------------------UniBerry EMU Engine-------------------   //
//  Created by: Archana Berry                                   //
//  Architecture: x86 (16/32/64-bit)                            //
//  Version resource: v0.001_alpha                              //
//  File: arch/8086.h                                           //
//  Type: header[architecture]                                  //
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

// 8086.h

#ifndef ARCH_8086_H
#define ARCH_8086_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ==============================
// x86 Constants
// ==============================
#define X86_REG_EAX 0
#define X86_REG_ECX 1
#define X86_REG_EDX 2
#define X86_REG_EBX 3
#define X86_REG_ESP 4
#define X86_REG_EBP 5
#define X86_REG_ESI 6
#define X86_REG_EDI 7
#define X86_REG_EIP 8
#define X86_REG_EFLAGS 9

#define X86_REG_RAX 0
#define X86_REG_RCX 1
#define X86_REG_RDX 2
#define X86_REG_RBX 3
#define X86_REG_RSP 4
#define X86_REG_RBP 5
#define X86_REG_RSI 6
#define X86_REG_RDI 7
#define X86_REG_R8  8
#define X86_REG_R9  9
#define X86_REG_R10 10
#define X86_REG_R11 11
#define X86_REG_R12 12
#define X86_REG_R13 13
#define X86_REG_R14 14
#define X86_REG_R15 15
#define X86_REG_RIP 16
#define X86_REG_RFLAGS 17

// Segment Registers
#define X86_REG_CS 0
#define X86_REG_DS 1
#define X86_REG_ES 2
#define X86_REG_SS 3
#define X86_REG_FS 4
#define X86_REG_GS 5

// Control Registers
#define X86_REG_CR0 0
#define X86_REG_CR2 2
#define X86_REG_CR3 3
#define X86_REG_CR4 4

// ==============================
// x86 Context Structure
// ==============================
typedef struct {
    // General Purpose Registers
    union {
        uint32_t e[8];  // 32-bit
        uint64_t r[16]; // 64-bit
    } gp;
    
    // Segment Registers
    uint16_t cs;
    uint16_t ds;
    uint16_t es;
    uint16_t ss;
    uint16_t fs;
    uint16_t gs;
    
    // Control Registers
    uint32_t cr0;
    uint32_t cr2;
    uint32_t cr3;
    uint32_t cr4;
    
    // EFLAGS/RFLAGS
    uint64_t flags;
    
    // Instruction Pointer
    uint64_t ip;
    
    // FPU/MMX/XMM
    union {
        uint8_t  mmx[64];    // MMX registers
        uint32_t fpu[28];    // FPU registers
        uint64_t xmm[16][2]; // XMM registers (128-bit)
        uint64_t ymm[16][4]; // YMM registers (256-bit)
    } simd;
    
    // Execution Mode
    bool real_mode;
    bool protected_mode;
    bool long_mode;
    bool v86_mode;
    
    // Descriptor Tables
    uint64_t gdt_base;
    uint16_t gdt_limit;
    uint64_t idt_base;
    uint16_t idt_limit;
    uint64_t ldt_base;
    uint16_t ldt_limit;
    uint64_t tr_base;
    uint16_t tr_limit;
    
    // Paging
    bool paging_enabled;
    uint64_t page_directory_base;
    
    // Interrupt State
    bool interrupts_enabled;
    uint8_t interrupt_mask;
    bool nmi_mask;
    
    // Debug State
    uint64_t debug_registers[8];
    bool breakpoint_hit;
    uint64_t breakpoint_addr;
    
    // Performance Counters
    uint64_t cycle_count;
    uint64_t instr_count;
    uint64_t branch_count;
} X86State;

// ==============================
// x86 Emulation Functions
// ==============================
typedef struct X86Emulator X86Emulator;

// Creation & Destruction
X86Emulator* x86_create_emulator(int mode, size_t mem_size);
void x86_destroy_emulator(X86Emulator *emu);

// Memory Management
int x86_map_memory(X86Emulator *emu, uint64_t addr, size_t size, 
                  bool read, bool write, bool exec);
int x86_load_binary(X86Emulator *emu, const uint8_t *data, size_t size, 
                   uint64_t load_addr);

// Register Access
int x86_read_register(X86Emulator *emu, int reg, uint64_t *value);
int x86_write_register(X86Emulator *emu, int reg, uint64_t value);
int x86_read_memory(X86Emulator *emu, uint64_t addr, void *buffer, size_t size);
int x86_write_memory(X86Emulator *emu, uint64_t addr, const void *buffer, size_t size);

// Execution
int x86_execute(X86Emulator *emu, uint64_t start_addr, uint64_t end_addr,
               size_t max_instructions, size_t *instr_executed);
int x86_step(X86Emulator *emu, size_t *instr_executed);

// State Management
int x86_save_state(X86Emulator *emu, X86State *state);
int x86_restore_state(X86Emulator *emu, const X86State *state);

// System Control
int x86_reset(X86Emulator *emu);
int x86_set_breakpoint(X86Emulator *emu, uint64_t addr);
int x86_clear_breakpoint(X86Emulator *emu, uint64_t addr);

// Interrupt Handling
int x86_trigger_interrupt(X86Emulator *emu, uint8_t vector);
int x86_set_interrupt_handler(X86Emulator *emu, 
                             void (*handler)(void *user, int vector),
                             void *user);

// Mode Switching
int x86_switch_to_real_mode(X86Emulator *emu);
int x86_switch_to_protected_mode(X86Emulator *emu);
int x86_switch_to_long_mode(X86Emulator *emu);

// I/O Port Access
int x86_read_port(X86Emulator *emu, uint16_t port, uint8_t *value, size_t size);
int x86_write_port(X86Emulator *emu, uint16_t port, const uint8_t *value, size_t size);

// Debug & Trace
int x86_disassemble(X86Emulator *emu, uint64_t addr, size_t count, 
                   char **output);
int x86_trace_enable(X86Emulator *emu, bool enable);
int x86_get_perf_stats(X86Emulator *emu, uint64_t *cycles, 
                      uint64_t *instructions, uint64_t *branches);

// ==============================
// Architecture Detection
// ==============================
uint64_t x86_16_detect_entry(const uint8_t *data, size_t size);
uint64_t x86_32_detect_entry(const uint8_t *data, size_t size);
uint64_t x86_64_detect_entry(const uint8_t *data, size_t size);

// ==============================
// Baremetal Execution
// ==============================
int x86_execute_baremetal(const uint8_t *code, size_t size, uint64_t entry,
                         int mode, size_t mem_size, bool verbose, uint64_t *result);

#ifdef __cplusplus
}
#endif

#endif /* ARCH_8086_H */
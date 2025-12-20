/****************************************************************/
//                                                              //
//  -------------------UniBerry EMU Engine-------------------   //
//  Created by: Archana Berry                                   //
//  Engine credits: Unicorn, Capstone, Keystone                 //
//  Version resource: v0.001_alpha                              //
//  File: ubemu.h                                               //
//  Type: header[engine]                                        //
//  Desc: Unified Berry Emulation Execution Machine Engine      //
//                                                              //
//  ----------------------------------------------------------  //
//                                                              //
//  ---- Do not use this as a template for commercial      ---- //
//  ---- projects without Archana Berry's permission,      ---- //
//  ---- except for educational purposes, research, or     ---- //
//  ---- contributing to the open-source community.        ---- //
//                                                              //
/****************************************************************/
//                                                              //
//  Patiently awaiting the release of UniBerryEMU               //
//                                                              //
/****************************************************************/

// ubemu.h

#ifndef UBEMU_H
#define UBEMU_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ==============================
// Engine Types & Constants
// ==============================
typedef enum {
    UBE_ARCH_UNKNOWN = 0,
    UBE_ARCH_X86_16,
    UBE_ARCH_X86_32,
    UBE_ARCH_X86_64,
    UBE_ARCH_ARM32,
    UBE_ARCH_ARM64,
    UBE_ARCH_MIPS32,
    UBE_ARCH_MIPS64,
    UBE_ARCH_RISCV32,
    UBE_ARCH_RISCV64,
    UBE_ARCH_PPC32,
    UBE_ARCH_PPC64
} ube_arch_t;

typedef enum {
    UBE_MODE_REAL = 0x1,
    UBE_MODE_PROTECTED = 0x2,
    UBE_MODE_LONG = 0x4,
    UBE_MODE_ARM = 0x8,
    UBE_MODE_THUMB = 0x10,
    UBE_MODE_V8 = 0x20,
    UBE_MODE_BIG_ENDIAN = 0x40,
    UBE_MODE_LITTLE_ENDIAN = 0x80
} ube_mode_t;

typedef enum {
    UBE_ERR_OK = 0,
    UBE_ERR_INVALID_ARG,
    UBE_ERR_NO_MEMORY,
    UBE_ERR_ARCH_NOT_SUPPORTED,
    UBE_ERR_ENGINE_FAILED,
    UBE_ERR_MMU_FAULT,
    UBE_ERR_TIMEOUT,
    UBE_ERR_SYSCALL,
    UBE_ERR_INTERRUPT,
    UBE_ERR_HALTED
} ube_error_t;

// ==============================
// Callback Types
// ==============================
typedef bool (*ube_mmio_read_cb)(void *user, uint64_t addr, size_t size, uint8_t *value);
typedef bool (*ube_mmio_write_cb)(void *user, uint64_t addr, size_t size, const uint8_t *value);
typedef bool (*ube_syscall_cb)(void *user, uint32_t num, uint64_t *args, uint64_t *ret);
typedef bool (*ube_interrupt_cb)(void *user, uint32_t num, bool *handled);
typedef void (*ube_trace_cb)(void *user, uint64_t addr, const char *mnemonic, const char *op_str);
typedef bool (*ube_mem_access_cb)(void *user, uint64_t addr, size_t size, bool is_write, bool is_exec);

// ==============================
// Main Context Structure
// ==============================
typedef struct UBEContext UBEContext;
typedef struct UBEState UBEState;

// ==============================
// Creation & Destruction
// ==============================
UBEContext* ube_create_context(ube_arch_t arch, ube_mode_t mode, size_t mem_size);
void ube_destroy_context(UBEContext *ctx);

// ==============================
// Memory Management
// ==============================
ube_error_t ube_map_memory(UBEContext *ctx, uint64_t addr, size_t size, 
                          bool read, bool write, bool exec);
ube_error_t ube_unmap_memory(UBEContext *ctx, uint64_t addr, size_t size);
ube_error_t ube_load_binary(UBEContext *ctx, const uint8_t *data, size_t size, 
                           uint64_t load_addr);
ube_error_t ube_load_elf(UBEContext *ctx, const uint8_t *data, size_t size);

// ==============================
// Register Access
// ==============================
ube_error_t ube_read_register(UBEContext *ctx, int reg_id, uint64_t *value);
ube_error_t ube_write_register(UBEContext *ctx, int reg_id, uint64_t value);
ube_error_t ube_read_memory(UBEContext *ctx, uint64_t addr, void *buffer, size_t size);
ube_error_t ube_write_memory(UBEContext *ctx, uint64_t addr, const void *buffer, size_t size);

// ==============================
// Execution Control
// ==============================
ube_error_t ube_run(UBEContext *ctx, uint64_t start_addr, uint64_t end_addr,
                   size_t *instr_count, uint64_t timeout_ms);
ube_error_t ube_step(UBEContext *ctx, size_t *instr_count);
ube_error_t ube_pause(UBEContext *ctx);
ube_error_t ube_resume(UBEContext *ctx);
ube_error_t ube_reset(UBEContext *ctx);

// ==============================
// Disassembly & Assembly
// ==============================
ube_error_t ube_disassemble(UBEContext *ctx, const uint8_t *code, size_t size,
                           uint64_t addr, char *output, size_t output_size);
ube_error_t ube_assemble(UBEContext *ctx, const char *assembly, uint64_t addr,
                        uint8_t **code, size_t *code_size);

// ==============================
// Callback Registration
// ==============================
ube_error_t ube_set_mmio_handler(UBEContext *ctx, uint64_t base, size_t size,
                                ube_mmio_read_cb read_cb,
                                ube_mmio_write_cb write_cb,
                                void *user);
ube_error_t ube_set_syscall_handler(UBEContext *ctx, ube_syscall_cb cb, void *user);
ube_error_t ube_set_interrupt_handler(UBEContext *ctx, ube_interrupt_cb cb, void *user);
ube_error_t ube_set_trace_handler(UBEContext *ctx, ube_trace_cb cb, void *user);
ube_error_t ube_set_mem_access_handler(UBEContext *ctx, ube_mem_access_cb cb, void *user);

// ==============================
// Architecture Detection
// ==============================
ube_arch_t ube_detect_architecture(const uint8_t *data, size_t size);
uint64_t ube_detect_entry_point(const uint8_t *data, size_t size, ube_arch_t arch);

// ==============================
// State Management (for save/restore)
// ==============================
UBEState* ube_save_state(UBEContext *ctx);
ube_error_t ube_restore_state(UBEContext *ctx, const UBEState *state);
void ube_free_state(UBEState *state);

// ==============================
// Debug & Info
// ==============================
ube_error_t ube_get_instruction_count(UBEContext *ctx, uint64_t *count);
ube_error_t ube_get_registers(UBEContext *ctx, uint64_t *regs, size_t count);
ube_error_t ube_print_registers(UBEContext *ctx);
ube_error_t ube_dump_memory(UBEContext *ctx, uint64_t addr, size_t size);
const char* ube_error_string(ube_error_t err);

#ifdef __cplusplus
}
#endif

#endif /* UBEMU_H */
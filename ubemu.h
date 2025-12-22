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
//---
/* ===================== ubemu.h ===================== */

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
    UBE_ARCH_RISCV32,
    UBE_ARCH_RISCV64,
    UBE_ARCH_MIPS32,
    UBE_ARCH_MIPS64,
    UBE_ARCH_PPC32,
    UBE_ARCH_PPC64
} ube_arch_t;

typedef enum {
    UBE_MODE_REAL        = 0x0001,
    UBE_MODE_PROTECTED   = 0x0002,
    UBE_MODE_LONG        = 0x0004, /* legacy: 64-bit long mode */

    /* Explicit x86 width modes (added to fix missing defines) */
    UBE_MODE_16          = 0x0010,
    UBE_MODE_32          = 0x0020,
    UBE_MODE_64          = 0x0040,

    UBE_MODE_ARM         = 0x0080,
    UBE_MODE_THUMB       = 0x0100,
    UBE_MODE_V8          = 0x0200, /* ARM64 / AArch64 */

    UBE_MODE_BIG_ENDIAN  = 0x0400,
    UBE_MODE_LITTLE_ENDIAN = 0x0800
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
// Main Context Structure
// ==============================
typedef struct UBEContext UBEContext;

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
ube_error_t ube_load_binary(UBEContext *ctx, const uint8_t *data, size_t size, 
                           uint64_t load_addr);

// ==============================
// Register Access (stubs)
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

// ==============================
// Disassembly & Assembly
// ==============================
ube_error_t ube_disassemble(UBEContext *ctx, const uint8_t *code, size_t size,
                           uint64_t addr, char *output, size_t output_size);

// ==============================
// Binary Format Detection
// ==============================
typedef enum {
    BIN_FORMAT_UNKNOWN = 0,
    BIN_FORMAT_ELF,
    BIN_FORMAT_PE,
    BIN_FORMAT_MACHO,
    BIN_FORMAT_FLAT,
    BIN_FORMAT_COM,
    BIN_FORMAT_MZ,
    BIN_FORMAT_DOS
} bin_format_t;

// ==============================
// Architecture Detection
// ==============================
ube_arch_t ube_detect_architecture(const uint8_t *data, size_t size);
bin_format_t ube_detect_format(const uint8_t *data, size_t size);
const char* ube_format_string(bin_format_t format);

// ==============================
// Architecture Functions (external)
// ==============================
uint64_t aarch32_detect_entry(const uint8_t *data, size_t size);
uint64_t aarch64_detect_entry(const uint8_t *data, size_t size);
uint64_t x86_16_detect_entry(const uint8_t *data, size_t size);
uint64_t x86_32_detect_entry(const uint8_t *data, size_t size);
uint64_t x86_64_detect_entry(const uint8_t *data, size_t size);

// ==============================
// Error Strings
// ==============================
const char* ube_error_string(ube_error_t err);

#ifdef __cplusplus
}
#endif

#endif /* UBEMU_H */
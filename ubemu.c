/****************************************************************/
//                                                              //
//  -------------------UniBerry EMU Engine-------------------   //
//  Created by: Archana Berry                                   //
//  Engine credits: Unicorn, Capstone, Keystone                 //
//  Version resource: v0.001_alpha                              //
//  File: ubemu.c                                               //
//  Type: source[engine]                                        //
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

// ubemu.c

#include "ubemu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>

// ==============================
// Engine Headers (conditional)
// ==============================
#ifdef HAS_CAPSTONE
#include <capstone/capstone.h>
#endif

#ifdef HAS_KEYSTONE
#include <keystone/keystone.h>
#endif

#ifdef HAS_UNICORN
#include <unicorn/unicorn.h>
#endif

// ==============================
// Internal Structures
// ==============================
typedef struct {
    uint64_t base;
    size_t size;
    uint8_t *data;
    bool read;
    bool write;
    bool exec;
    ube_mmio_read_cb read_cb;
    ube_mmio_write_cb write_cb;
    void *user;
} MemoryRegion;

typedef struct {
    uint64_t start;
    uint64_t end;
    ube_trace_cb cb;
    void *user;
} TraceInfo;

struct UBEContext {
    // Engine handles
#ifdef HAS_UNICORN
    uc_engine *uc;
#endif
#ifdef HAS_CAPSTONE
    csh cs;
#endif
#ifdef HAS_KEYSTONE
    ks_engine *ks;
#endif
    
    // Architecture info
    ube_arch_t arch;
    ube_mode_t mode;
    
    // Memory management
    MemoryRegion *regions;
    size_t region_count;
    size_t max_regions;
    
    // Callbacks
    ube_syscall_cb syscall_cb;
    ube_interrupt_cb interrupt_cb;
    ube_trace_cb trace_cb;
    ube_mem_access_cb mem_access_cb;
    void *syscall_user;
    void *interrupt_user;
    void *trace_user;
    void *mem_access_user;
    
    // Execution state
    bool running;
    bool paused;
    uint64_t instr_count;
    uint64_t start_time;
    
    // Configuration
    size_t mem_size;
    uint64_t entry_point;
    bool verbose;
};

struct UBEState {
    uint8_t *data;
    size_t size;
    ube_arch_t arch;
};

// ==============================
// Helper Functions
// ==============================
static ube_arch_t host_architecture(void) {
#ifdef __x86_64__
    return UBE_ARCH_X86_64;
#elif defined(__i386__)
    return UBE_ARCH_X86_32;
#elif defined(__aarch64__)
    return UBE_ARCH_ARM64;
#elif defined(__arm__)
    return UBE_ARCH_ARM32;
#elif defined(__mips__)
    #ifdef __mips64
        return UBE_ARCH_MIPS64;
    #else
        return UBE_ARCH_MIPS32;
    #endif
#elif defined(__riscv)
    #if __riscv_xlen == 64
        return UBE_ARCH_RISCV64;
    #else
        return UBE_ARCH_RISCV32;
    #endif
#elif defined(__powerpc64__)
    return UBE_ARCH_PPC64;
#elif defined(__powerpc__)
    return UBE_ARCH_PPC32;
#else
    return UBE_ARCH_UNKNOWN;
#endif
}

static const char* arch_to_string(ube_arch_t arch) {
    switch (arch) {
        case UBE_ARCH_X86_16: return "x86_16";
        case UBE_ARCH_X86_32: return "x86_32";
        case UBE_ARCH_X86_64: return "x86_64";
        case UBE_ARCH_ARM32: return "arm32";
        case UBE_ARCH_ARM64: return "arm64";
        case UBE_ARCH_MIPS32: return "mips32";
        case UBE_ARCH_MIPS64: return "mips64";
        case UBE_ARCH_RISCV32: return "riscv32";
        case UBE_ARCH_RISCV64: return "riscv64";
        case UBE_ARCH_PPC32: return "ppc32";
        case UBE_ARCH_PPC64: return "ppc64";
        default: return "unknown";
    }
}

// ==============================
// Creation & Destruction
// ==============================
UBEContext* ube_create_context(ube_arch_t arch, ube_mode_t mode, size_t mem_size) {
    UBEContext *ctx = calloc(1, sizeof(UBEContext));
    if (!ctx) return NULL;
    
    ctx->arch = arch;
    ctx->mode = mode;
    ctx->mem_size = mem_size;
    ctx->max_regions = 16;
    
    ctx->regions = calloc(ctx->max_regions, sizeof(MemoryRegion));
    if (!ctx->regions) {
        free(ctx);
        return NULL;
    }
    
#ifdef HAS_UNICORN
    uc_arch uc_arch;
    uc_mode uc_mode = 0;
    
    // Map architecture
    switch (arch) {
        case UBE_ARCH_X86_16:
            uc_arch = UC_ARCH_X86;
            uc_mode = UC_MODE_16;
            break;
        case UBE_ARCH_X86_32:
            uc_arch = UC_ARCH_X86;
            uc_mode = UC_MODE_32;
            break;
        case UBE_ARCH_X86_64:
            uc_arch = UC_ARCH_X86;
            uc_mode = UC_MODE_64;
            break;
        case UBE_ARCH_ARM32:
            uc_arch = UC_ARCH_ARM;
            uc_mode = (mode & UBE_MODE_THUMB) ? UC_MODE_THUMB : UC_MODE_ARM;
            break;
        case UBE_ARCH_ARM64:
            uc_arch = UC_ARCH_ARM64;
            uc_mode = UC_MODE_ARM;
            break;
        case UBE_ARCH_MIPS32:
            uc_arch = UC_ARCH_MIPS;
            uc_mode = UC_MODE_MIPS32;
            break;
        case UBE_ARCH_MIPS64:
            uc_arch = UC_ARCH_MIPS;
            uc_mode = UC_MODE_MIPS64;
            break;
        default:
            free(ctx->regions);
            free(ctx);
            return NULL;
    }
    
    // Add endianness
    if (mode & UBE_MODE_BIG_ENDIAN) {
        uc_mode |= UC_MODE_BIG_ENDIAN;
    } else {
        uc_mode |= UC_MODE_LITTLE_ENDIAN;
    }
    
    uc_err err = uc_open(uc_arch, uc_mode, &ctx->uc);
    if (err != UC_ERR_OK) {
        free(ctx->regions);
        free(ctx);
        return NULL;
    }
#endif
    
#ifdef HAS_CAPSTONE
    cs_arch cs_arch;
    cs_mode cs_mode = 0;
    
    switch (arch) {
        case UBE_ARCH_X86_16:
            cs_arch = CS_ARCH_X86;
            cs_mode = CS_MODE_16;
            break;
        case UBE_ARCH_X86_32:
            cs_arch = CS_ARCH_X86;
            cs_mode = CS_MODE_32;
            break;
        case UBE_ARCH_X86_64:
            cs_arch = CS_ARCH_X86;
            cs_mode = CS_MODE_64;
            break;
        case UBE_ARCH_ARM32:
            cs_arch = CS_ARCH_ARM;
            cs_mode = (mode & UBE_MODE_THUMB) ? CS_MODE_THUMB : CS_MODE_ARM;
            break;
        case UBE_ARCH_ARM64:
            cs_arch = CS_ARCH_ARM64;
            cs_mode = CS_MODE_ARM;
            break;
        default:
            break;
    }
    
    if (cs_arch != 0) {
        if (cs_open(cs_arch, cs_mode, &ctx->cs) != CS_ERR_OK) {
            ctx->cs = 0;
        }
        cs_option(ctx->cs, CS_OPT_DETAIL, CS_OPT_OFF);
    }
#endif
    
#ifdef HAS_KEYSTONE
    ks_arch ks_arch;
    ks_mode ks_mode = 0;
    
    switch (arch) {
        case UBE_ARCH_X86_16:
            ks_arch = KS_ARCH_X86;
            ks_mode = KS_MODE_16;
            break;
        case UBE_ARCH_X86_32:
            ks_arch = KS_ARCH_X86;
            ks_mode = KS_MODE_32;
            break;
        case UBE_ARCH_X86_64:
            ks_arch = KS_ARCH_X86;
            ks_mode = KS_MODE_64;
            break;
        case UBE_ARCH_ARM32:
            ks_arch = KS_ARCH_ARM;
            ks_mode = (mode & UBE_MODE_THUMB) ? KS_MODE_THUMB : KS_MODE_ARM;
            break;
        case UBE_ARCH_ARM64:
            ks_arch = KS_ARCH_ARM64;
            ks_mode = KS_MODE_LITTLE_ENDIAN;
            break;
        default:
            break;
    }
    
    if (ks_arch != 0) {
        if (ks_open(ks_arch, ks_mode, &ctx->ks) != KS_ERR_OK) {
            ctx->ks = NULL;
        }
    }
#endif
    
    return ctx;
}

void ube_destroy_context(UBEContext *ctx) {
    if (!ctx) return;
    
#ifdef HAS_UNICORN
    if (ctx->uc) uc_close(ctx->uc);
#endif
    
#ifdef HAS_CAPSTONE
    if (ctx->cs) cs_close(&ctx->cs);
#endif
    
#ifdef HAS_KEYSTONE
    if (ctx->ks) ks_close(ctx->ks);
#endif
    
    for (size_t i = 0; i < ctx->region_count; i++) {
        if (ctx->regions[i].data) {
            free(ctx->regions[i].data);
        }
    }
    
    free(ctx->regions);
    free(ctx);
}

// ==============================
// Memory Management
// ==============================
ube_error_t ube_map_memory(UBEContext *ctx, uint64_t addr, size_t size, 
                          bool read, bool write, bool exec) {
    if (!ctx || size == 0) return UBE_ERR_INVALID_ARG;
    
    // Check for overlap
    for (size_t i = 0; i < ctx->region_count; i++) {
        if (addr < ctx->regions[i].base + ctx->regions[i].size &&
            addr + size > ctx->regions[i].base) {
            return UBE_ERR_INVALID_ARG;
        }
    }
    
    // Grow region array if needed
    if (ctx->region_count >= ctx->max_regions) {
        size_t new_max = ctx->max_regions * 2;
        MemoryRegion *new_regions = realloc(ctx->regions, new_max * sizeof(MemoryRegion));
        if (!new_regions) return UBE_ERR_NO_MEMORY;
        ctx->regions = new_regions;
        ctx->max_regions = new_max;
    }
    
    // Allocate memory
    uint8_t *data = calloc(1, size);
    if (!data) return UBE_ERR_NO_MEMORY;
    
    // Add region
    MemoryRegion *region = &ctx->regions[ctx->region_count++];
    region->base = addr;
    region->size = size;
    region->data = data;
    region->read = read;
    region->write = write;
    region->exec = exec;
    region->read_cb = NULL;
    region->write_cb = NULL;
    region->user = NULL;
    
#ifdef HAS_UNICORN
    // Map in unicorn
    int prot = 0;
    if (read) prot |= UC_PROT_READ;
    if (write) prot |= UC_PROT_WRITE;
    if (exec) prot |= UC_PROT_EXEC;
    
    uc_err err = uc_mem_map_ptr(ctx->uc, addr, size, prot, data);
    if (err != UC_ERR_OK) {
        free(data);
        ctx->region_count--;
        return UBE_ERR_ENGINE_FAILED;
    }
#endif
    
    return UBE_ERR_OK;
}

ube_error_t ube_load_binary(UBEContext *ctx, const uint8_t *data, size_t size, 
                           uint64_t load_addr) {
    if (!ctx || !data || size == 0) return UBE_ERR_INVALID_ARG;
    
    // Find region containing load_addr
    for (size_t i = 0; i < ctx->region_count; i++) {
        MemoryRegion *region = &ctx->regions[i];
        if (load_addr >= region->base && 
            load_addr + size <= region->base + region->size &&
            region->write) {
            
            memcpy(region->data + (load_addr - region->base), data, size);
            return UBE_ERR_OK;
        }
    }
    
    // No suitable region found
    return UBE_ERR_INVALID_ARG;
}

// ==============================
// Register Access
// ==============================
ube_error_t ube_read_register(UBEContext *ctx, int reg_id, uint64_t *value) {
    if (!ctx || !value) return UBE_ERR_INVALID_ARG;
    
#ifdef HAS_UNICORN
    uc_err err = uc_reg_read(ctx->uc, reg_id, value);
    return (err == UC_ERR_OK) ? UBE_ERR_OK : UBE_ERR_ENGINE_FAILED;
#else
    return UBE_ERR_ENGINE_FAILED;
#endif
}

ube_error_t ube_write_register(UBEContext *ctx, int reg_id, uint64_t value) {
    if (!ctx) return UBE_ERR_INVALID_ARG;
    
#ifdef HAS_UNICORN
    uc_err err = uc_reg_write(ctx->uc, reg_id, &value);
    return (err == UC_ERR_OK) ? UBE_ERR_OK : UBE_ERR_ENGINE_FAILED;
#else
    return UBE_ERR_ENGINE_FAILED;
#endif
}

// ==============================
// Execution Control
// ==============================
ube_error_t ube_run(UBEContext *ctx, uint64_t start_addr, uint64_t end_addr,
                   size_t *instr_count, uint64_t timeout_ms) {
    if (!ctx) return UBE_ERR_INVALID_ARG;
    
#ifdef HAS_UNICORN
    uc_err err;
    
    if (end_addr == 0) {
        err = uc_emu_start(ctx->uc, start_addr, 0, 0, 0);
    } else {
        err = uc_emu_start(ctx->uc, start_addr, end_addr, 0, 0);
    }
    
    if (err != UC_ERR_OK && err != UC_ERR_EXCEPTION) {
        return UBE_ERR_ENGINE_FAILED;
    }
    
    if (instr_count) {
        // Get instruction count from unicorn if available
        *instr_count = ctx->instr_count;
    }
    
    return UBE_ERR_OK;
#else
    return UBE_ERR_ENGINE_FAILED;
#endif
}

// ==============================
// Disassembly & Assembly
// ==============================
ube_error_t ube_disassemble(UBEContext *ctx, const uint8_t *code, size_t size,
                           uint64_t addr, char *output, size_t output_size) {
    if (!ctx || !code || !output || output_size == 0) {
        return UBE_ERR_INVALID_ARG;
    }
    
#ifdef HAS_CAPSTONE
    if (!ctx->cs) return UBE_ERR_ENGINE_FAILED;
    
    cs_insn *insn;
    size_t count = cs_disasm(ctx->cs, code, size, addr, 1, &insn);
    
    if (count > 0) {
        snprintf(output, output_size, "0x%" PRIx64 ": %s %s", 
                insn[0].address, insn[0].mnemonic, insn[0].op_str);
        cs_free(insn, count);
        return UBE_ERR_OK;
    }
#endif
    
    return UBE_ERR_ENGINE_FAILED;
}

// ==============================
// Architecture Detection
// ==============================
ube_arch_t ube_detect_architecture(const uint8_t *data, size_t size) {
    if (!data || size < 4) return UBE_ARCH_UNKNOWN;
    
    // Check ELF header
    if (size >= SELFMAG && memcmp(data, ELFMAG, SELFMAG) == 0) {
        if (size >= EI_CLASS + 1) {
            uint8_t elf_class = data[EI_CLASS];
            if (size >= 0x13) {
                uint16_t e_machine = *(uint16_t*)(data + 0x12);
                switch (e_machine) {
                    case EM_386: return UBE_ARCH_X86_32;
                    case EM_X86_64: return UBE_ARCH_X86_64;
                    case EM_ARM: return UBE_ARCH_ARM32;
                    case EM_AARCH64: return UBE_ARCH_ARM64;
                    case EM_MIPS: return UBE_ARCH_MIPS32;
                    case EM_MIPS_RS3_LE: return UBE_ARCH_MIPS64;
                    case EM_RISCV: return (elf_class == ELFCLASS32) ? 
                                          UBE_ARCH_RISCV32 : UBE_ARCH_RISCV64;
                    case EM_PPC: return UBE_ARCH_PPC32;
                    case EM_PPC64: return UBE_ARCH_PPC64;
                }
            }
        }
    }
    
    // Heuristic detection for flat binaries
    // Check for x86 opcode patterns
    for (size_t i = 0; i + 2 <= size; i++) {
        if (data[i] == 0xCD && data[i+1] == 0x80) { // int 0x80 (x86 32-bit)
            return UBE_ARCH_X86_32;
        }
        if (data[i] == 0x0F && data[i+1] == 0x05) { // syscall (x86 64-bit)
            return UBE_ARCH_X86_64;
        }
    }
    
    return host_architecture();
}

// ==============================
// Error Strings
// ==============================
const char* ube_error_string(ube_error_t err) {
    switch (err) {
        case UBE_ERR_OK: return "Success";
        case UBE_ERR_INVALID_ARG: return "Invalid argument";
        case UBE_ERR_NO_MEMORY: return "Out of memory";
        case UBE_ERR_ARCH_NOT_SUPPORTED: return "Architecture not supported";
        case UBE_ERR_ENGINE_FAILED: return "Engine failed";
        case UBE_ERR_MMU_FAULT: return "MMU fault";
        case UBE_ERR_TIMEOUT: return "Timeout";
        case UBE_ERR_SYSCALL: return "System call";
        case UBE_ERR_INTERRUPT: return "Interrupt";
        case UBE_ERR_HALTED: return "Halted";
        default: return "Unknown error";
    }
}
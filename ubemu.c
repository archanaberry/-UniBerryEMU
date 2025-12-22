// ubemu.c - Perbaikan dari kesalahan kompilasi

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

// ubemu.c - Main program for UniBerry EMU Engine (Complete Version)

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

#include "ubemu.h"
#include "target/elf.h"
#include "target/pm.h"
#include "target/macho.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#include <ctype.h>
#include <inttypes.h>

// ==============================
// Engine Headers (conditional)
// ==============================
#ifdef HAS_CAPSTONE
#include <capstone/capstone.h>
#else
// Fallback if Capstone not available
typedef void* csh;
#define CS_ARCH_X86 0
#define CS_ARCH_ARM 1
#define CS_ARCH_ARM64 2
#define CS_MODE_16 0
#define CS_MODE_32 1
#define CS_MODE_64 2
#define CS_MODE_THUMB 4
#define CS_MODE_ARM 0
#endif

#ifdef HAS_KEYSTONE
#include <keystone/keystone.h>
#else
typedef void* ks_engine;
#define KS_ARCH_X86 0
#define KS_ARCH_ARM 1
#define KS_ARCH_ARM64 2
#define KS_MODE_16 0
#define KS_MODE_32 1
#define KS_MODE_64 2
#define KS_MODE_THUMB 4
#define KS_MODE_ARM 0
#endif

#ifdef HAS_UNICORN
#include <unicorn/unicorn.h>
#else
typedef void* uc_engine;
#define UC_ARCH_X86 0
#define UC_ARCH_ARM 1
#define UC_ARCH_ARM64 2
#define UC_MODE_16 0
#define UC_MODE_32 1
#define UC_MODE_64 2
#define UC_MODE_THUMB 4
#define UC_MODE_ARM 0
#define UC_PROT_READ 1
#define UC_PROT_WRITE 2
#define UC_PROT_EXEC 4
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
} MemoryRegion;

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

// ==============================
// Global Configuration
// ==============================
typedef struct {
    const char *filename;
    bin_format_t format;
    ube_arch_t arch;
    ube_mode_t mode;
    uint64_t entry_point;
    size_t mem_size;
    bool verbose;
    bool auto_detect;
    bool disassemble;
    bool step_mode;
    uint64_t timeout_ms;
    size_t max_instructions;
    bool show_info_only;
} UBEConfig;

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
        case UBE_ARCH_RISCV32: return "riscv32";
        case UBE_ARCH_RISCV64: return "riscv64";
        case UBE_ARCH_MIPS32: return "mips32";
        case UBE_ARCH_MIPS64: return "mips64";
        case UBE_ARCH_PPC32: return "ppc32";
        case UBE_ARCH_PPC64: return "ppc64";
        default: return "unknown";
    }
}

static const char* mode_to_string(ube_mode_t mode) {
    static char buf[128];
    buf[0] = '\0';
    
    if (mode & UBE_MODE_REAL) strcat(buf, "real ");
    if (mode & UBE_MODE_PROTECTED) strcat(buf, "protected ");
    if (mode & UBE_MODE_LONG) strcat(buf, "long ");
    if (mode & UBE_MODE_ARM) strcat(buf, "arm ");
    if (mode & UBE_MODE_THUMB) strcat(buf, "thumb ");
    if (mode & UBE_MODE_V8) strcat(buf, "v8 ");
    if (mode & UBE_MODE_BIG_ENDIAN) strcat(buf, "big-endian ");
    if (mode & UBE_MODE_LITTLE_ENDIAN) strcat(buf, "little-endian ");
    
    if (buf[0] == '\0') strcpy(buf, "default");
    
    return buf;
}

static void print_banner(void) {
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                   UniBerry EMU Engine v0.001_alpha            ║\n");
    printf("║            Universal Binary Execution Machine                 ║\n");
    printf("║         Created by: Archana Berry                             ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

static void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS] <binary_file>\n", program_name);
    printf("\n");
    printf("Universal Binary Emulator - Supports multiple architectures and formats\n");
    printf("\n");
    printf("Format Options (optional, auto-detect by default):\n");
    printf("  -elf, --elf        Force ELF format (Linux/Unix binaries)\n");
    printf("  -pm, --pm          Force PE/MZ format (Windows executables)\n");
    printf("  -mo, --macho       Force Mach-O format (macOS binaries)\n");
    printf("  -flat, --flat      Force flat binary format\n");
    printf("\n");
    printf("Architecture Options (optional, auto-detect by default):\n");
    printf("  -x86               Force x86 32-bit architecture\n");
    printf("  -x64               Force x86-64 architecture\n");
    printf("  -arm               Force ARM 32-bit architecture\n");
    printf("  -arm64             Force ARM64 architecture\n");
    printf("  -mips              Force MIPS architecture\n");
    printf("\n");
    printf("Mode Options:\n");
    printf("  -16                Force 16-bit mode (x86)\n");
    printf("  -32                Force 32-bit mode\n");
    printf("  -64                Force 64-bit mode\n");
    printf("  -thumb             Force Thumb mode (ARM)\n");
    printf("  -be                Force big-endian mode\n");
    printf("  -le                Force little-endian mode\n");
    printf("\n");
    printf("Execution Options:\n");
    printf("  -eauto, --eauto    Auto-detect OS and format (default)\n");
    printf("  -e <addr>          Entry point address (hexadecimal, default: auto)\n");
    printf("  -m <size>          Memory size in MB (default: 64)\n");
    printf("  -t <ms>            Timeout in milliseconds (default: 10000)\n");
    printf("  -step              Step-by-step execution mode\n");
    printf("  -disasm            Disassemble before execution\n");
    printf("  -v, --verbose      Verbose output\n");
    printf("  -limit <N>         Maximum instruction count (default: 10000000)\n");
    printf("\n");
    printf("Information:\n");
    printf("  -h, --help         Show this help message\n");
    printf("  -info              Show binary information without execution\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -elf linux_program          # ELF binary\n", program_name);
    printf("  %s -pm windows.exe             # Windows executable\n", program_name);
    printf("  %s -mo macos_binary            # macOS Mach-O binary\n", program_name);
    printf("  %s -eauto program.bin          # Auto-detect format\n", program_name);
    printf("  %s -x64 -flat kernel.bin       # Force x64 flat binary\n", program_name);
    printf("  %s -arm -thumb firmware.bin    # ARM Thumb binary\n", program_name);
    printf("\n");
}

// ==============================
// File Loading
// ==============================
static uint8_t* load_file(const char *filename, size_t *size) {
    if (!filename || !size) {
        fprintf(stderr, "Error: Invalid parameters for load_file\n");
        return NULL;
    }
    
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open file '%s': %s\n", filename, strerror(errno));
        return NULL;
    }
    
    struct stat st;
    if (fstat(fd, &st) < 0) {
        fprintf(stderr, "Failed to stat file '%s': %s\n", filename, strerror(errno));
        close(fd);
        return NULL;
    }
    
    if (st.st_size == 0) {
        fprintf(stderr, "Error: File '%s' is empty\n", filename);
        close(fd);
        return NULL;
    }
    
    *size = st.st_size;
    uint8_t *data = mmap(NULL, *size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    
    if (data == MAP_FAILED) {
        fprintf(stderr, "Failed to mmap file '%s': %s\n", filename, strerror(errno));
        return NULL;
    }
    
    return data;
}

static void unload_file(uint8_t *data, size_t size) {
    if (data && size > 0) {
        munmap(data, size);
    }
}

// ==============================
// Creation & Destruction
// ==============================
UBEContext* ube_create_context(ube_arch_t arch, ube_mode_t mode, size_t mem_size) {
    UBEContext *ctx = calloc(1, sizeof(UBEContext));
    if (!ctx) {
        fprintf(stderr, "Failed to allocate UBEContext\n");
        return NULL;
    }
    
    ctx->arch = arch;
    ctx->mode = mode;
    ctx->mem_size = mem_size;
    ctx->max_regions = 16;
    
    ctx->regions = calloc(ctx->max_regions, sizeof(MemoryRegion));
    if (!ctx->regions) {
        fprintf(stderr, "Failed to allocate memory regions\n");
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
            fprintf(stderr, "Unsupported architecture for Unicorn engine\n");
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
        fprintf(stderr, "Failed to initialize Unicorn engine: %u\n", err);
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
        case UBE_ARCH_MIPS32:
            cs_arch = CS_ARCH_MIPS;
            cs_mode = CS_MODE_MIPS32;
            break;
        case UBE_ARCH_MIPS64:
            cs_arch = CS_ARCH_MIPS;
            cs_mode = CS_MODE_MIPS64;
            break;
        default:
            cs_arch = 0;
            break;
    }
    
    if (cs_arch != 0) {
        if (cs_open(cs_arch, cs_mode, &ctx->cs) != CS_ERR_OK) {
            fprintf(stderr, "Warning: Failed to initialize Capstone engine\n");
            ctx->cs = 0;
        } else {
            cs_option(ctx->cs, CS_OPT_DETAIL, CS_OPT_OFF);
        }
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
            ks_arch = 0;
            break;
    }
    
    if (ks_arch != 0) {
        if (ks_open(ks_arch, ks_mode, &ctx->ks) != KS_ERR_OK) {
            fprintf(stderr, "Warning: Failed to initialize Keystone engine\n");
            ctx->ks = NULL;
        }
    }
#endif
    
    printf("Created context for architecture: %s, mode: %s\n", 
           arch_to_string(arch), mode_to_string(mode));
    
    return ctx;
}

void ube_destroy_context(UBEContext *ctx) {
    if (!ctx) return;
    
    printf("Destroying emulation context...\n");
    
#ifdef HAS_UNICORN
    if (ctx->uc) {
        uc_close(ctx->uc);
    }
#endif
    
#ifdef HAS_CAPSTONE
    if (ctx->cs) {
        cs_close(&ctx->cs);
    }
#endif
    
#ifdef HAS_KEYSTONE
    if (ctx->ks) {
        ks_close(ctx->ks);
    }
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
            fprintf(stderr, "Memory region overlap detected: 0x%" PRIx64 "-0x%" PRIx64 "\n",
                   addr, addr + size);
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
    if (!data) {
        fprintf(stderr, "Failed to allocate %zu bytes of memory\n", size);
        return UBE_ERR_NO_MEMORY;
    }
    
    // Add region
    MemoryRegion *region = &ctx->regions[ctx->region_count++];
    region->base = addr;
    region->size = size;
    region->data = data;
    region->read = read;
    region->write = write;
    region->exec = exec;
    
    printf("Mapped memory at 0x%" PRIx64 " size: %zu bytes (R:%d W:%d X:%d)\n",
           addr, size, read, write, exec);
    
#ifdef HAS_UNICORN
    // Map in unicorn
    int prot = 0;
    if (read) prot |= UC_PROT_READ;
    if (write) prot |= UC_PROT_WRITE;
    if (exec) prot |= UC_PROT_EXEC;
    
    uc_err err = uc_mem_map_ptr(ctx->uc, addr, size, prot, data);
    if (err != UC_ERR_OK) {
        fprintf(stderr, "Failed to map memory in Unicorn: %u\n", err);
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
            
            uint64_t offset = load_addr - region->base;
            memcpy(region->data + offset, data, size);
            
            printf("Loaded binary at 0x%" PRIx64 " (offset: 0x%" PRIx64 "), size: %zu bytes\n",
                   load_addr, offset, size);
            
#ifdef HAS_UNICORN
            // Also write to Unicorn engine
            uc_err err = uc_mem_write(ctx->uc, load_addr, data, size);
            if (err != UC_ERR_OK) {
                fprintf(stderr, "Warning: Failed to write binary to Unicorn memory\n");
            }
#endif
            
            return UBE_ERR_OK;
        }
    }
    
    // No suitable region found, create one
    uint64_t aligned_addr = load_addr & ~(0xFFFULL); // Align to 4KB
    size_t aligned_size = ((size + 0xFFF) & ~0xFFF); // Round up to 4KB
    
    ube_error_t err = ube_map_memory(ctx, aligned_addr, aligned_size, true, true, true);
    if (err != UBE_ERR_OK) {
        fprintf(stderr, "Failed to create memory region for binary\n");
        return err;
    }
    
    // Now load the binary
    for (size_t i = 0; i < ctx->region_count; i++) {
        MemoryRegion *region = &ctx->regions[i];
        if (load_addr >= region->base && 
            load_addr + size <= region->base + region->size &&
            region->write) {
            
            uint64_t offset = load_addr - region->base;
            memcpy(region->data + offset, data, size);
            
            printf("Created and loaded binary at 0x%" PRIx64 ", size: %zu bytes\n",
                   load_addr, size);
            
#ifdef HAS_UNICORN
            uc_err uc_err = uc_mem_write(ctx->uc, load_addr, data, size);
            if (uc_err != UC_ERR_OK) {
                fprintf(stderr, "Warning: Failed to write binary to Unicorn memory\n");
            }
#endif
            
            return UBE_ERR_OK;
        }
    }
    
    fprintf(stderr, "Failed to load binary at 0x%" PRIx64 "\n", load_addr);
    return UBE_ERR_INVALID_ARG;
}

// ==============================
// Execution Control
// ==============================
ube_error_t ube_run(UBEContext *ctx, uint64_t start_addr, uint64_t end_addr,
                   size_t *instr_count, uint64_t timeout_ms) {
    if (!ctx) return UBE_ERR_INVALID_ARG;
    
#ifdef HAS_UNICORN
    uc_err err;
    
    printf("Starting emulation at 0x%" PRIx64, start_addr);
    if (end_addr != 0) {
        printf(" until 0x%" PRIx64, end_addr);
    }
    printf("\n");
    
    if (end_addr == 0) {
        err = uc_emu_start(ctx->uc, start_addr, 0, 0, 0);
    } else {
        err = uc_emu_start(ctx->uc, start_addr, end_addr, 0, 0);
    }
    
    if (err != UC_ERR_OK && err != UC_ERR_EXCEPTION) {
        fprintf(stderr, "Emulation failed with error: %u\n", err);
        return UBE_ERR_ENGINE_FAILED;
    }
    
    if (instr_count) {
        *instr_count = ctx->instr_count;
    }
    
    return UBE_ERR_OK;
#else
    fprintf(stderr, "Unicorn engine not available for execution\n");
    (void)start_addr; (void)end_addr; (void)instr_count; (void)timeout_ms;
    return UBE_ERR_ENGINE_FAILED;
#endif
}

ube_error_t ube_step(UBEContext *ctx, size_t *instr_count) {
    if (!ctx) return UBE_ERR_INVALID_ARG;
    
#ifdef HAS_UNICORN
    uc_err err = uc_emu_start(ctx->uc, 0, 0, 1, 0);
    if (err != UC_ERR_OK && err != UC_ERR_EXCEPTION) {
        fprintf(stderr, "Step execution failed with error: %u\n", err);
        return UBE_ERR_ENGINE_FAILED;
    }
    
    if (instr_count) {
        *instr_count = 1;
        ctx->instr_count++;
    }
    
    return UBE_ERR_OK;
#else
    fprintf(stderr, "Unicorn engine not available for stepping\n");
    (void)instr_count;
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
    
    // Fallback: simple hex dump
    (void)ctx; (void)addr;
    snprintf(output, output_size, "0x%04lx: ", (unsigned long)addr);
    
    size_t pos = strlen(output);
    for (size_t i = 0; i < (size < 8 ? size : 8) && pos < output_size - 3; i++) {
        snprintf(output + pos, output_size - pos, "%02x ", code[i]);
        pos += 3;
    }
    
    return UBE_ERR_OK;
}

// ==============================
// Heuristic architecture detection for flat binaries
// ==============================
static ube_arch_t detect_architecture_flat(const uint8_t *data, size_t size) {
    if (!data || size < 4) return UBE_ARCH_UNKNOWN;
    
    // Check for x86 opcode patterns
    for (size_t i = 0; i + 2 <= size; i++) {
        if (data[i] == 0xCD && data[i+1] == 0x80) { // int 0x80 (x86 32-bit)
            return UBE_ARCH_X86_32;
        }
        if (data[i] == 0x0F && data[i+1] == 0x05) { // syscall (x86 64-bit)
            return UBE_ARCH_X86_64;
        }
        // ARM detection
        if (i + 4 <= size) {
            uint32_t word;
            memcpy(&word, data + i, sizeof(uint32_t));
            // ARM branch instruction pattern
            if ((word & 0xFF000000) == 0xEA000000) {
                return UBE_ARCH_ARM32;
            }
            // Thumb branch
            if ((word & 0xF800) == 0xE000) {
                return UBE_ARCH_ARM32;
            }
        }
    }
    
    return host_architecture();
}

// ==============================
// Binary Format Detection
// ==============================
bin_format_t ube_detect_format(const uint8_t *data, size_t size) {
    if (!data || size < 4) return BIN_FORMAT_UNKNOWN;
    
    // Check ELF (0x7F 'E' 'L' 'F')
    if (size >= 4 && memcmp(data, "\x7F" "ELF", 4) == 0) {
        return BIN_FORMAT_ELF;
    }
    
    // Check MZ/PE ("MZ")
    if (size >= 2 && memcmp(data, "MZ", 2) == 0) {
        return BIN_FORMAT_MZ;
    }
    
    // Check Mach-O
    if (size >= 4) {
        uint32_t magic;
        memcpy(&magic, data, sizeof(uint32_t));
        if (magic == 0xFEEDFACE || magic == 0xFEEDFACF || 
            magic == 0xCEFAEDFE || magic == 0xCFFAEDFE) {
            return BIN_FORMAT_MACHO;
        }
    }
    
    // Check DOS COM (simple heuristic)
    if (size < 65536 && size > 0) {
        // Check for DOS COM signature (often starts with jump instruction)
        if (size >= 2 && data[0] == 0xEB && data[1] < 0x80) { // Short jump
            return BIN_FORMAT_COM;
        }
    }
    
    return BIN_FORMAT_FLAT;
}

const char* ube_format_string(bin_format_t format) {
    switch (format) {
        case BIN_FORMAT_ELF: return "ELF";
        case BIN_FORMAT_PE: return "PE";
        case BIN_FORMAT_MACHO: return "Mach-O";
        case BIN_FORMAT_FLAT: return "Flat Binary";
        case BIN_FORMAT_COM: return "DOS COM";
        case BIN_FORMAT_MZ: return "MZ/EXE";
        case BIN_FORMAT_DOS: return "DOS";
        default: return "Unknown";
    }
}

// ==============================
// Architecture Detection
// ==============================
ube_arch_t ube_detect_architecture(const uint8_t *data, size_t size) {
    bin_format_t format = ube_detect_format(data, size);
    
    // Use appropriate parser based on format
    switch (format) {
        case BIN_FORMAT_ELF:
            return elf_detect_architecture(data, size);
        case BIN_FORMAT_PE:
        case BIN_FORMAT_MZ:
            return pe_detect_architecture(data, size);
        case BIN_FORMAT_MACHO:
            return macho_detect_architecture(data, size);
        default:
            // Fallback to heuristic detection for flat binaries
            return detect_architecture_flat(data, size);
    }
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

// ==============================
// Configuration and Analysis
// ==============================
static void analyze_binary(const char *filename, uint8_t *data, size_t size, UBEConfig *config) {
    printf("\n[+] Binary Analysis:\n");
    printf("    File: %s\n", filename);
    printf("    Size: %zu bytes (%.2f KB, %.2f MB)\n", 
           size, size / 1024.0, size / (1024.0 * 1024.0));
    
    bin_format_t format = ube_detect_format(data, size);
    printf("    Format: %s\n", ube_format_string(format));
    
    ube_arch_t arch = ube_detect_architecture(data, size);
    printf("    Architecture: %s\n", arch_to_string(arch));
    
    // Get entry point based on format
    uint64_t entry_point = 0;
    switch (format) {
        case BIN_FORMAT_ELF:
            entry_point = elf_get_entry_point(data, size);
            break;
        case BIN_FORMAT_PE:
        case BIN_FORMAT_MZ:
            entry_point = pe_get_entry_point(data, size);
            break;
        case BIN_FORMAT_MACHO:
            entry_point = macho_get_entry_point(data, size);
            break;
        default:
            entry_point = 0x1000; // Default for flat binaries
    }
    
    printf("    Entry Point: 0x%" PRIx64 "\n", entry_point);
    printf("    Host Architecture: %s\n", arch_to_string(host_architecture()));
    
    // Show first few bytes for verification
    printf("    First 16 bytes: ");
    for (size_t i = 0; i < (size < 16 ? size : 16); i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
    
    // Update config if auto-detect
    if (config->auto_detect) {
        config->format = format;
        config->arch = arch;
        config->entry_point = entry_point;
    }
}

static int parse_arguments(int argc, char *argv[], UBEConfig *config) {
    static struct option long_options[] = {
        {"elf", no_argument, 0, 'E'},
        {"pm", no_argument, 0, 'P'},
        {"macho", no_argument, 0, 'M'},
        {"flat", no_argument, 0, 'F'},
        {"x86", no_argument, 0, 1000},
        {"x64", no_argument, 0, 1001},
        {"arm", no_argument, 0, 1002},
        {"arm64", no_argument, 0, 1003},
        {"mips", no_argument, 0, 1004},
        {"16", no_argument, 0, 1005},
        {"32", no_argument, 0, 1006},
        {"64", no_argument, 0, 1007},
        {"thumb", no_argument, 0, 1008},
        {"be", no_argument, 0, 1009},
        {"le", no_argument, 0, 1010},
        {"eauto", no_argument, 0, 'a'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"info", no_argument, 0, 'i'},
        {0, 0, 0, 0}
    };
    
    int opt;
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "EPMFXYABe:m:t:s:dvl:iha", 
                              long_options, &option_index)) != -1) {
        switch (opt) {
            case 'E':
                config->format = BIN_FORMAT_ELF;
                config->auto_detect = false;
                break;
            case 'P':
                config->format = BIN_FORMAT_PE;
                config->auto_detect = false;
                break;
            case 'M':
                config->format = BIN_FORMAT_MACHO;
                config->auto_detect = false;
                break;
            case 'F':
                config->format = BIN_FORMAT_FLAT;
                config->auto_detect = false;
                break;
            case 1000: // --x86
                config->arch = UBE_ARCH_X86_32;
                break;
            case 1001: // --x64
                config->arch = UBE_ARCH_X86_64;
                break;
            case 1002: // --arm
                config->arch = UBE_ARCH_ARM32;
                break;
            case 1003: // --arm64
                config->arch = UBE_ARCH_ARM64;
                break;
            case 1004: // --mips
                config->arch = UBE_ARCH_MIPS32;
                break;
            case 1005: // --16
                config->mode |= UBE_MODE_16;
                break;
            case 1006: // --32
                config->mode |= UBE_MODE_32;
                break;
            case 1007: // --64
                config->mode |= UBE_MODE_64;
                break;
            case 1008: // --thumb
                config->mode |= UBE_MODE_THUMB;
                break;
            case 1009: // --be
                config->mode |= UBE_MODE_BIG_ENDIAN;
                break;
            case 1010: // --le
                config->mode |= UBE_MODE_LITTLE_ENDIAN;
                break;
            case 'a':
                config->auto_detect = true;
                break;
            case 'e':
                config->entry_point = strtoull(optarg, NULL, 16);
                break;
            case 'm':
                config->mem_size = atoi(optarg) * 1024 * 1024;
                if (config->mem_size == 0) {
                    fprintf(stderr, "Error: Invalid memory size\n");
                    return -1;
                }
                break;
            case 't':
                config->timeout_ms = strtoull(optarg, NULL, 10);
                break;
            case 's':
                config->step_mode = true;
                break;
            case 'd':
                config->disassemble = true;
                break;
            case 'v':
                config->verbose = true;
                break;
            case 'l':
                config->max_instructions = strtoull(optarg, NULL, 10);
                break;
            case 'i':
                config->show_info_only = true;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                fprintf(stderr, "Unknown option: %c\n", opt);
                print_usage(argv[0]);
                return -1;
        }
    }
    
    if (optind >= argc) {
        fprintf(stderr, "Error: No binary file specified\n");
        print_usage(argv[0]);
        return -1;
    }
    
    config->filename = argv[optind];
    return 0;
}

static ube_mode_t get_default_mode_for_arch(ube_arch_t arch) {
    ube_mode_t mode = 0;
    
    switch (arch) {
        case UBE_ARCH_X86_16:
            mode = UBE_MODE_16;
            break;
        case UBE_ARCH_X86_32:
            mode = UBE_MODE_32;
            break;
        case UBE_ARCH_X86_64:
            mode = UBE_MODE_64;
            break;
        case UBE_ARCH_ARM32:
            mode = UBE_MODE_ARM;
            break;
        case UBE_ARCH_ARM64:
            mode = UBE_MODE_ARM;
            break;
        default:
            mode = 0;
            break;
    }
    
    // Default to little-endian if not specified
    if (!(mode & (UBE_MODE_BIG_ENDIAN | UBE_MODE_LITTLE_ENDIAN))) {
        mode |= UBE_MODE_LITTLE_ENDIAN;
    }
    
    return mode;
}

static void run_emulation(UBEContext *ctx, UBEConfig *config, uint8_t *binary_data, size_t binary_size) {
    printf("\n[+] Starting Emulation...\n");
    
    // Map memory (default at 0x1000)
    ube_error_t err = ube_map_memory(ctx, 0x1000, config->mem_size, true, true, true);
    if (err != UBE_ERR_OK) {
        fprintf(stderr, "Failed to map memory: %s\n", ube_error_string(err));
        return;
    }
    
    // Load binary
    err = ube_load_binary(ctx, binary_data, binary_size, config->entry_point);
    if (err != UBE_ERR_OK) {
        fprintf(stderr, "Failed to load binary: %s\n", ube_error_string(err));
        return;
    }
    
    printf("    Binary loaded at 0x%" PRIx64 "\n", config->entry_point);
    printf("    Memory size: %zu MB\n", config->mem_size / (1024 * 1024));
    
    // Disassemble first few instructions if requested
    if (config->disassemble) {
        printf("\n[+] Disassembly (first 10 instructions):\n");
        for (int i = 0; i < 10 && i * 4 < (int)binary_size; i++) {
            char disasm[256];
            if (ube_disassemble(ctx, binary_data + i * 4, 16, 
                               config->entry_point + i * 4, disasm, sizeof(disasm)) == UBE_ERR_OK) {
                printf("    0x%04lx: %s\n", (unsigned long)(config->entry_point + i * 4), disasm);
            }
        }
    }
    
    // Run emulation
    if (config->step_mode) {
        printf("\n[+] Step mode enabled. Press Enter to step, 'q' to quit.\n");
        size_t step_count = 0;
        
        while (1) {
            printf("\nStep %zu: ", ++step_count);
            
            // Wait for user input
            int c = getchar();
            if (c == 'q' || c == 'Q') {
                printf("User requested quit\n");
                break;
            }
            
            size_t instr_executed;
            err = ube_step(ctx, &instr_executed);
            if (err != UBE_ERR_OK) {
                printf("Emulation stopped: %s\n", ube_error_string(err));
                break;
            }
            
            if (step_count >= config->max_instructions) {
                printf("Maximum instruction count reached (%zu)\n", config->max_instructions);
                break;
            }
        }
    } else {
        printf("\n[+] Running emulation...\n");
        printf("    Timeout: %" PRIu64 " ms\n", config->timeout_ms);
        printf("    Max instructions: %zu\n", config->max_instructions);
        
        clock_t start = clock();
        
        size_t instr_executed = 0;
        err = ube_run(ctx, config->entry_point, 0, &instr_executed, config->timeout_ms);
        
        clock_t end = clock();
        double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
        
        if (err != UBE_ERR_OK) {
            printf("Emulation stopped: %s\n", ube_error_string(err));
        } else {
            printf("Emulation completed successfully\n");
        }
        
        printf("    Instructions executed: %zu\n", instr_executed);
        printf("    Time elapsed: %.3f seconds\n", elapsed);
        if (elapsed > 0) {
            printf("    IPS: %.0f instructions/second\n", instr_executed / elapsed);
        }
    }
}

// ==============================
// Main Program
// ==============================
int main(int argc, char *argv[]) {
    print_banner();
    
    // Default configuration
    UBEConfig config = {
        .filename = NULL,
        .format = BIN_FORMAT_UNKNOWN,
        .arch = UBE_ARCH_UNKNOWN,
        .mode = 0,
        .entry_point = 0x1000,
        .mem_size = 64 * 1024 * 1024, // 64 MB
        .verbose = false,
        .auto_detect = true, // Auto-detect by default
        .disassemble = false,
        .step_mode = false,
        .timeout_ms = 10000, // 10 seconds
        .max_instructions = 10000000,
        .show_info_only = false
    };
    
    // Parse command line arguments
    if (parse_arguments(argc, argv, &config) != 0) {
        return 1;
    }
    
    // Load binary file
    size_t binary_size = 0;
    uint8_t *binary_data = load_file(config.filename, &binary_size);
    if (!binary_data) {
        fprintf(stderr, "Failed to load file: %s\n", config.filename);
        return 1;
    }
    
    // Analyze binary
    analyze_binary(config.filename, binary_data, binary_size, &config);
    
    // If just showing info, exit here
    if (config.show_info_only) {
        printf("\n[+] Info mode - No emulation will be performed.\n");
        unload_file(binary_data, binary_size);
        return 0;
    }
    
    // If architecture is still unknown, use auto-detection
    if (config.arch == UBE_ARCH_UNKNOWN) {
        config.arch = ube_detect_architecture(binary_data, binary_size);
        printf("    Auto-detected architecture: %s\n", arch_to_string(config.arch));
    }
    
    // Get mode for architecture
    if (config.mode == 0) {
        config.mode = get_default_mode_for_arch(config.arch);
    }
    
    printf("    Using mode: %s\n", mode_to_string(config.mode));
    
    // Create emulation context
    printf("\n[+] Creating emulation context...\n");
    UBEContext *ctx = ube_create_context(config.arch, config.mode, config.mem_size);
    if (!ctx) {
        fprintf(stderr, "Failed to create emulation context\n");
        unload_file(binary_data, binary_size);
        return 1;
    }
    
    ctx->verbose = config.verbose;
    
    // Run emulation
    run_emulation(ctx, &config, binary_data, binary_size);
    
    // Cleanup
    printf("\n[+] Cleaning up...\n");
    ube_destroy_context(ctx);
    unload_file(binary_data, binary_size);
    
    printf("\n[+] Emulation session completed.\n");
    return 0;
}
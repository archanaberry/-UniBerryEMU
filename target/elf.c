/****************************************************************/
//                                                              //
//  -------------------UniBerry EMU Engine-------------------  //
//  Created by: Archana Berry                                   //
//  Format: ELF (Executable and Linkable Format)                //
//  Version resource: v0.001_alpha                              //
//  File: target/elf.c                                          //
//  Type: source[binary parser]                                 //
//  Desc: ELF binary format parser implementation               //
//                                                              //
//  ----------------------------------------------------------  //
//                                                              //
//  ---- Implements ELF32/ELF64 parsing, segment loading,   ----//
//  ---- memory mapping, and architecture detection for     ----//
//  ---- Linux/Unix executables and shared objects.         ----//
//                                                              //
/****************************************************************/
//                                                              //
//  Patiently awaiting the release of UniBerryEMU.c             //
//                                                              //
/****************************************************************/

#include "elf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>

// ==============================
// ELF Constants
// ==============================
#define EI_NIDENT 16
#define ELFMAG "\177ELF"
#define SELFMAG 4

// e_ident indices
#define EI_CLASS     4
#define EI_DATA      5
#define EI_VERSION   6
#define EI_OSABI     7
#define EI_ABIVERSION 8

// ELF class
#define ELFCLASSNONE 0
#define ELFCLASS32   1
#define ELFCLASS64   2

// ELF data encoding
#define ELFDATANONE  0
#define ELFDATA2LSB  1
#define ELFDATA2MSB  2

// ELF types
#define ET_NONE   0
#define ET_REL    1
#define ET_EXEC   2
#define ET_DYN    3
#define ET_CORE   4

// Machine types
#define EM_NONE   0
#define EM_386    3
#define EM_X86_64 62
#define EM_ARM    40
#define EM_AARCH64 183
#define EM_MIPS   8
#define EM_PPC    20
#define EM_PPC64  21
#define EM_RISCV  243

// Program header types
#define PT_NULL    0
#define PT_LOAD    1
#define PT_DYNAMIC 2
#define PT_INTERP  3
#define PT_NOTE    4
#define PT_SHLIB   5
#define PT_PHDR    6
#define PT_TLS     7

// Program header flags
#define PF_X 0x1
#define PF_W 0x2
#define PF_R 0x4

// ==============================
// Helper Functions
// ==============================
static uint16_t read_u16(const uint8_t *data, bool is_big_endian) {
    if (is_big_endian) {
        return (data[0] << 8) | data[1];
    } else {
        return data[0] | (data[1] << 8);
    }
}

static uint32_t read_u32(const uint8_t *data, bool is_big_endian) {
    if (is_big_endian) {
        return (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    } else {
        return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
    }
}

static uint64_t read_u64(const uint8_t *data, bool is_big_endian) {
    if (is_big_endian) {
        return ((uint64_t)data[0] << 56) | ((uint64_t)data[1] << 48) |
               ((uint64_t)data[2] << 40) | ((uint64_t)data[3] << 32) |
               ((uint64_t)data[4] << 24) | ((uint64_t)data[5] << 16) |
               ((uint64_t)data[6] << 8) | data[7];
    } else {
        return data[0] | ((uint64_t)data[1] << 8) | ((uint64_t)data[2] << 16) |
               ((uint64_t)data[3] << 24) | ((uint64_t)data[4] << 32) |
               ((uint64_t)data[5] << 40) | ((uint64_t)data[6] << 48) |
               ((uint64_t)data[7] << 56);
    }
}

// ==============================
// ELF Detection
// ==============================
bool elf_is_valid(const uint8_t *data, size_t size) {
    if (size < SELFMAG) return false;
    return memcmp(data, ELFMAG, SELFMAG) == 0;
}

ube_arch_t elf_detect_architecture(const uint8_t *data, size_t size) {
    if (!elf_is_valid(data, size)) return UBE_ARCH_UNKNOWN;
    
    if (size < EI_CLASS + 1) return UBE_ARCH_UNKNOWN;
    uint8_t elf_class = data[EI_CLASS];
    
    if (size >= 0x13) {
        uint16_t e_machine = read_u16(data + 0x12, false); // Assume little-endian for detection
        
        switch (e_machine) {
            case EM_386:
                return UBE_ARCH_X86_32;
            case EM_X86_64:
                return UBE_ARCH_X86_64;
            case EM_ARM:
                return UBE_ARCH_ARM32;
            case EM_AARCH64:
                return UBE_ARCH_ARM64;
            case EM_RISCV:
                return (elf_class == ELFCLASS32) ? UBE_ARCH_RISCV32 : UBE_ARCH_RISCV64;
            case EM_MIPS:
                return (elf_class == ELFCLASS32) ? UBE_ARCH_MIPS32 : UBE_ARCH_MIPS64;
            case EM_PPC:
                return UBE_ARCH_PPC32;
            case EM_PPC64:
                return UBE_ARCH_PPC64;
            default:
                return UBE_ARCH_UNKNOWN;
        }
    }
    
    return UBE_ARCH_UNKNOWN;
}

uint64_t elf_get_entry_point(const uint8_t *data, size_t size) {
    if (!elf_is_valid(data, size)) return 0;
    
    uint8_t elf_class = data[EI_CLASS];
    bool is_big_endian = (data[EI_DATA] == ELFDATA2MSB);
    
    if (elf_class == ELFCLASS32 && size >= 24) {
        // 32-bit ELF: entry at offset 24
        return read_u32(data + 24, is_big_endian);
    } else if (elf_class == ELFCLASS64 && size >= 24) {
        // 64-bit ELF: entry at offset 24
        return read_u64(data + 24, is_big_endian);
    }
    
    return 0;
}

uint64_t elf_get_base_address(const uint8_t *data, size_t size) {
    if (!elf_is_valid(data, size)) return 0;
    
    uint8_t elf_class = data[EI_CLASS];
    bool is_big_endian = (data[EI_DATA] == ELFDATA2MSB);
    uint64_t base_addr = 0xFFFFFFFFFFFFFFFF;
    
    // Find the lowest loadable segment address
    if (size >= 32) {
        uint16_t e_phoff = read_u16(data + 28, is_big_endian);
        uint16_t e_phentsize = read_u16(data + 42, is_big_endian);
        uint16_t e_phnum = read_u16(data + 44, is_big_endian);
        
        if (elf_class == ELFCLASS32) {
            for (int i = 0; i < e_phnum; i++) {
                size_t offset = e_phoff + i * e_phentsize;
                if (offset + 32 <= size) {
                    uint32_t p_type = read_u32(data + offset, is_big_endian);
                    uint32_t p_vaddr = read_u32(data + offset + 8, is_big_endian);
                    
                    if (p_type == PT_LOAD && p_vaddr < base_addr) {
                        base_addr = p_vaddr;
                    }
                }
            }
        } else if (elf_class == ELFCLASS64) {
            for (int i = 0; i < e_phnum; i++) {
                size_t offset = e_phoff + i * e_phentsize;
                if (offset + 56 <= size) {
                    uint32_t p_type = read_u32(data + offset, is_big_endian);
                    uint64_t p_vaddr = read_u64(data + offset + 16, is_big_endian);
                    
                    if (p_type == PT_LOAD && p_vaddr < base_addr) {
                        base_addr = p_vaddr;
                    }
                }
            }
        }
    }
    
    return (base_addr == 0xFFFFFFFFFFFFFFFF) ? 0 : base_addr;
}

// ==============================
// ELF Loading
// ==============================
int elf_load_segments(UBEContext *ctx, const uint8_t *data, size_t size) {
    if (!ctx || !data || !elf_is_valid(data, size)) return -1;
    
    uint8_t elf_class = data[EI_CLASS];
    bool is_big_endian = (data[EI_DATA] == ELFDATA2MSB);
    
    if (size < 32) return -1;
    
    uint16_t e_phoff = read_u16(data + 28, is_big_endian);
    uint16_t e_phentsize = read_u16(data + 42, is_big_endian);
    uint16_t e_phnum = read_u16(data + 44, is_big_endian);
    
    int loaded = 0;
    
    if (elf_class == ELFCLASS32) {
        for (int i = 0; i < e_phnum; i++) {
            size_t offset = e_phoff + i * e_phentsize;
            if (offset + 32 <= size) {
                uint32_t p_type = read_u32(data + offset, is_big_endian);
                uint32_t p_offset = read_u32(data + offset + 4, is_big_endian);
                uint32_t p_vaddr = read_u32(data + offset + 8, is_big_endian);
                uint32_t p_filesz = read_u32(data + offset + 16, is_big_endian);
                uint32_t p_flags = read_u32(data + offset + 24, is_big_endian);
                
                if (p_type == PT_LOAD && p_filesz > 0) {
                    bool read = (p_flags & PF_R) != 0;
                    bool write = (p_flags & PF_W) != 0;
                    bool exec = (p_flags & PF_X) != 0;
                    
                    // Map memory
                    ube_map_memory(ctx, p_vaddr, p_filesz, read, write, exec);
                    
                    // Load data
                    if (p_offset + p_filesz <= size) {
                        ube_load_binary(ctx, data + p_offset, p_filesz, p_vaddr);
                        loaded++;
                    }
                }
            }
        }
    } else if (elf_class == ELFCLASS64) {
        for (int i = 0; i < e_phnum; i++) {
            size_t offset = e_phoff + i * e_phentsize;
            if (offset + 56 <= size) {
                uint32_t p_type = read_u32(data + offset, is_big_endian);
                uint32_t p_flags = read_u32(data + offset + 4, is_big_endian);
                uint64_t p_offset = read_u64(data + offset + 8, is_big_endian);
                uint64_t p_vaddr = read_u64(data + offset + 16, is_big_endian);
                uint64_t p_filesz = read_u64(data + offset + 32, is_big_endian);
                
                if (p_type == PT_LOAD && p_filesz > 0) {
                    bool read = (p_flags & PF_R) != 0;
                    bool write = (p_flags & PF_W) != 0;
                    bool exec = (p_flags & PF_X) != 0;
                    
                    // Map memory
                    ube_map_memory(ctx, p_vaddr, p_filesz, read, write, exec);
                    
                    // Load data
                    if (p_offset + p_filesz <= size) {
                        ube_load_binary(ctx, data + p_offset, p_filesz, p_vaddr);
                        loaded++;
                    }
                }
            }
        }
    }
    
    return (loaded > 0) ? 0 : -1;
}

// ==============================
// Architecture-specific Functions
// ==============================
uint64_t elf_aarch32_detect_entry(const uint8_t *data, size_t size) {
    return elf_get_entry_point(data, size);
}

uint64_t elf_aarch64_detect_entry(const uint8_t *data, size_t size) {
    return elf_get_entry_point(data, size);
}

uint64_t elf_x86_32_detect_entry(const uint8_t *data, size_t size) {
    return elf_get_entry_point(data, size);
}

uint64_t elf_x86_64_detect_entry(const uint8_t *data, size_t size) {
    return elf_get_entry_point(data, size);
}
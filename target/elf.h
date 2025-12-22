/****************************************************************/
//                                                              //
//  -------------------UniBerry EMU Engine-------------------  //
//  Created by: Archana Berry                                   //
//  Format: ELF (Executable and Linkable Format)                //
//  Version resource: v0.001_alpha                              //
//  File: target/elf.h                                          //
//  Type: header[binary parser]                                 //
//  Desc: ELF binary format parser for Unix/Linux systems       //
//                                                              //
//  ----------------------------------------------------------  //
//                                                              //
//  ---- Supports ELF32/ELF64, all architectures, sections, ----//
//  ---- segments, symbol tables, and dynamic linking.      ----//
//                                                              //
/****************************************************************/
//                                                              //
//  Patiently awaiting the release of UniBerryEMU.c             //
//                                                              //
/****************************************************************/

#ifndef TARGET_ELF_H
#define TARGET_ELF_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "../ubemu.h"

#ifdef __cplusplus
extern "C" {
#endif

// ==============================
// ELF Structures
// ==============================
typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr;

// ==============================
// ELF Detection Functions
// ==============================
bool elf_is_valid(const uint8_t *data, size_t size);
ube_arch_t elf_detect_architecture(const uint8_t *data, size_t size);
uint64_t elf_get_entry_point(const uint8_t *data, size_t size);
uint64_t elf_get_base_address(const uint8_t *data, size_t size);

// ==============================
// ELF Loading Functions
// ==============================
int elf_load_segments(UBEContext *ctx, const uint8_t *data, size_t size);
int elf_load_to_memory(UBEContext *ctx, const uint8_t *data, size_t size, 
                      uint64_t load_addr);

// ==============================
// ELF Information Functions
// ==============================
const char* elf_get_type_string(uint16_t type);
const char* elf_get_machine_string(uint16_t machine);
void elf_print_header(const uint8_t *data, size_t size);
void elf_print_segments(const uint8_t *data, size_t size);
void elf_print_sections(const uint8_t *data, size_t size);

// ==============================
// Architecture-specific ELF Functions
// ==============================
uint64_t elf_aarch32_detect_entry(const uint8_t *data, size_t size);
uint64_t elf_aarch64_detect_entry(const uint8_t *data, size_t size);
uint64_t elf_x86_32_detect_entry(const uint8_t *data, size_t size);
uint64_t elf_x86_64_detect_entry(const uint8_t *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* TARGET_ELF_H */
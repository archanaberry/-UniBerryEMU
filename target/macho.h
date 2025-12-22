/****************************************************************/
//                                                              //
//  -------------------UniBerry EMU Engine-------------------  //
//  Created by: Archana Berry                                   //
//  Format: Mach-O (Mach Object)                                //
//  Version resource: v0.001_alpha                              //
//  File: target/macho.h                                        //
//  Type: header[binary parser]                                 //
//  Desc: Mach-O binary format parser for Apple systems         //
//                                                              //
//  ----------------------------------------------------------  //
//                                                              //
//  ---- Supports Mach-O 32/64-bit, FAT binaries, universal ----//
//  ---- binaries, and macOS/iOS executable formats.         ----//
//                                                              //
/****************************************************************/
//                                                              //
//  Patiently awaiting the release of UniBerryEMU.c             //
//                                                              //
/****************************************************************/

#ifndef TARGET_MACHO_H
#define TARGET_MACHO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "../ubemu.h"

#ifdef __cplusplus
extern "C" {
#endif

// ==============================
// Mach-O Structures
// ==============================
typedef struct {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
} mach_header_64;

// ==============================
// Mach-O Detection Functions
// ==============================
bool macho_is_valid(const uint8_t *data, size_t size);
ube_arch_t macho_detect_architecture(const uint8_t *data, size_t size);
uint64_t macho_get_entry_point(const uint8_t *data, size_t size);
uint64_t macho_get_base_address(const uint8_t *data, size_t size);

// ==============================
// Mach-O Loading Functions
// ==============================
int macho_load_commands(UBEContext *ctx, const uint8_t *data, size_t size);
int macho_load_to_memory(UBEContext *ctx, const uint8_t *data, size_t size, 
                        uint64_t load_addr);

// ==============================
// Mach-O Information Functions
// ==============================
const char* macho_get_cputype_string(uint32_t cputype);
const char* macho_get_filetype_string(uint32_t filetype);
void macho_print_header(const uint8_t *data, size_t size);
void macho_print_load_commands(const uint8_t *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* TARGET_MACHO_H */
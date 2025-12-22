/****************************************************************/
//                                                              //
//  -------------------UniBerry EMU Engine-------------------  //
//  Created by: Archana Berry                                   //
//  Format: PE/MZ (Portable Executable)                         //
//  Version resource: v0.001_alpha                              //
//  File: target/pm.c                                           //
//  Type: source[binary parser]                                 //
//  Desc: PE/MZ binary format parser implementation             //
//                                                              //
//  ----------------------------------------------------------  //
//                                                              //
//  ---- Implements MZ DOS stub parsing, PE32/PE32+ header  ----//
//  ---- parsing, section loading, and Windows executable   ----//
//  ---- memory mapping for Windows binaries.               ----//
//                                                              //
/****************************************************************/
//                                                              //
//  Patiently awaiting the release of UniBerryEMU.c             //
//                                                              //
/****************************************************************/

#include "pm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ==============================
// PE/MZ Constants
// ==============================
#define IMAGE_DOS_SIGNATURE 0x5A4D      // "MZ"
#define IMAGE_NT_SIGNATURE 0x00004550   // "PE\0\0"

// Machine types
#define IMAGE_FILE_MACHINE_I386     0x014c
#define IMAGE_FILE_MACHINE_AMD64    0x8664
#define IMAGE_FILE_MACHINE_ARM      0x01c0
#define IMAGE_FILE_MACHINE_ARM64    0xaa64
#define IMAGE_FILE_MACHINE_ARMNT    0x01c4
#define IMAGE_FILE_MACHINE_THUMB    0x01c2

// ==============================
// Helper Functions
// ==============================
static uint16_t read_u16_le(const uint8_t *data) {
    return data[0] | (data[1] << 8);
}

static uint32_t read_u32_le(const uint8_t *data) {
    return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
}

// ==============================
// PE/MZ Detection
// ==============================
bool mz_is_valid(const uint8_t *data, size_t size) {
    if (size < 2) return false;
    return read_u16_le(data) == IMAGE_DOS_SIGNATURE;
}

bool pe_is_valid(const uint8_t *data, size_t size) {
    if (!mz_is_valid(data, size)) return false;
    
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)data;
    uint32_t pe_offset = dos->e_lfanew;
    
    if (pe_offset + 4 > size) return false;
    return read_u32_le(data + pe_offset) == IMAGE_NT_SIGNATURE;
}

ube_arch_t pe_detect_architecture(const uint8_t *data, size_t size) {
    if (!pe_is_valid(data, size)) {
        // Check if it's just MZ (DOS)
        if (mz_is_valid(data, size)) {
            return UBE_ARCH_X86_16;
        }
        return UBE_ARCH_UNKNOWN;
    }
    
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)data;
    uint32_t pe_offset = dos->e_lfanew;
    
    if (pe_offset + 6 > size) return UBE_ARCH_UNKNOWN;
    
    uint16_t machine = read_u16_le(data + pe_offset + 4);
    
    switch (machine) {
        case IMAGE_FILE_MACHINE_I386:
            return UBE_ARCH_X86_32;
        case IMAGE_FILE_MACHINE_AMD64:
            return UBE_ARCH_X86_64;
        case IMAGE_FILE_MACHINE_ARM:
        case IMAGE_FILE_MACHINE_ARMNT:
        case IMAGE_FILE_MACHINE_THUMB:
            return UBE_ARCH_ARM32;
        case IMAGE_FILE_MACHINE_ARM64:
            return UBE_ARCH_ARM64;
        default:
            return UBE_ARCH_UNKNOWN;
    }
}

uint64_t pe_get_entry_point(const uint8_t *data, size_t size) {
    if (!pe_is_valid(data, size)) {
        // MZ DOS entry point
        if (mz_is_valid(data, size) && size >= 32) {
            IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)data;
            return (dos->e_cs << 4) + dos->e_ip;
        }
        return 0;
    }
    
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)data;
    uint32_t pe_offset = dos->e_lfanew;
    
    if (pe_offset + 24 > size) return 0;
    
    uint16_t optional_header_size = read_u16_le(data + pe_offset + 16);
    
    // Check if it's PE32 or PE32+
    uint16_t magic = read_u16_le(data + pe_offset + 24);
    
    if (magic == 0x10b) { // PE32
        if (pe_offset + 40 > size) return 0;
        return read_u32_le(data + pe_offset + 40);
    } else if (magic == 0x20b) { // PE32+
        if (pe_offset + 40 > size) return 0;
        return read_u32_le(data + pe_offset + 40);
    }
    
    return 0;
}
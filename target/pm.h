/****************************************************************/
//                                                              //
//  -------------------UniBerry EMU Engine-------------------  //
//  Created by: Archana Berry                                   //
//  Format: PE/MZ (Portable Executable)                         //
//  Version resource: v0.001_alpha                              //
//  File: target/pm.h                                           //
//  Type: header[binary parser]                                 //
//  Desc: PE/MZ binary format parser for Windows systems        //
//                                                              //
//  ----------------------------------------------------------  //
//                                                              //
//  ---- Supports MZ DOS headers, PE32/PE32+ executables,   ----//
//  ---- DLLs, COFF object files, and Windows resources.    ----//
//                                                              //
/****************************************************************/
//                                                              //
//  Patiently awaiting the release of UniBerryEMU.c             //
//                                                              //
/****************************************************************/

#ifndef TARGET_PM_H
#define TARGET_PM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "../ubemu.h"

#ifdef __cplusplus
extern "C" {
#endif

// ==============================
// PE/MZ Structures
// ==============================
typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    uint32_t Signature;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} IMAGE_FILE_HEADER;

// ==============================
// PE/MZ Detection Functions
// ==============================
bool pe_is_valid(const uint8_t *data, size_t size);
bool mz_is_valid(const uint8_t *data, size_t size);
ube_arch_t pe_detect_architecture(const uint8_t *data, size_t size);
uint64_t pe_get_entry_point(const uint8_t *data, size_t size);
uint64_t pe_get_base_address(const uint8_t *data, size_t size);

// ==============================
// PE/MZ Loading Functions
// ==============================
int pe_load_sections(UBEContext *ctx, const uint8_t *data, size_t size);
int mz_load_to_memory(UBEContext *ctx, const uint8_t *data, size_t size, 
                     uint64_t load_addr);

// ==============================
// PE/MZ Information Functions
// ==============================
const char* pe_get_machine_string(uint16_t machine);
const char* pe_get_subsystem_string(uint16_t subsystem);
void pe_print_header(const uint8_t *data, size_t size);
void pe_print_sections(const uint8_t *data, size_t size);
void mz_print_header(const uint8_t *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* TARGET_PM_H */
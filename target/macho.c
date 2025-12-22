// target/macho.c
#include "macho.h"
#include <stdint.h>
#include <string.h>

ube_arch_t macho_detect_architecture(const uint8_t *data, size_t size) {
    if (size < 4) return UBE_ARCH_UNKNOWN;
    
    uint32_t magic;
    memcpy(&magic, data, sizeof(magic));
    
    // Mach-O magic numbers
    if (magic == 0xFEEDFACE || magic == 0xCEFAEDFE) { // 32-bit
        // Read CPU type (offset 4 from start)
        if (size >= 8) {
            uint32_t cputype;
            memcpy(&cputype, data + 4, sizeof(cputype));
            
            // Swap if big-endian
            if (magic == 0xCEFAEDFE) { // Big-endian
                cputype = ((cputype >> 24) & 0xFF) |
                         ((cputype >> 8) & 0xFF00) |
                         ((cputype << 8) & 0xFF0000) |
                         ((cputype << 24) & 0xFF000000);
            }
            
            switch (cputype) {
                case 7:  // CPU_TYPE_X86
                    return UBE_ARCH_X86_32;
                case 12: // CPU_TYPE_ARM
                    return UBE_ARCH_ARM32;
                case 18: // CPU_TYPE_POWERPC
                    return UBE_ARCH_PPC32;
                default:
                    return UBE_ARCH_UNKNOWN;
            }
        }
    } else if (magic == 0xFEEDFACF || magic == 0xCFFAEDFE) { // 64-bit
        // Read CPU type (offset 4 from start)
        if (size >= 8) {
            uint32_t cputype;
            memcpy(&cputype, data + 4, sizeof(cputype));
            
            // Swap if big-endian
            if (magic == 0xCFFAEDFE) { // Big-endian
                cputype = ((cputype >> 24) & 0xFF) |
                         ((cputype >> 8) & 0xFF00) |
                         ((cputype << 8) & 0xFF0000) |
                         ((cputype << 24) & 0xFF000000);
            }
            
            switch (cputype) {
                case 0x01000007: // CPU_TYPE_X86_64
                    return UBE_ARCH_X86_64;
                case 0x0100000C: // CPU_TYPE_ARM64
                    return UBE_ARCH_ARM64;
                case 0x01000012: // CPU_TYPE_POWERPC64
                    return UBE_ARCH_PPC64;
                default:
                    return UBE_ARCH_UNKNOWN;
            }
        }
    }
    
    return UBE_ARCH_UNKNOWN;
}

uint64_t macho_get_entry_point(const uint8_t *data, size_t size) {
    // Default entry point for Mach-O binaries
    (void)data;
    (void)size;
    return 0x1000;
}
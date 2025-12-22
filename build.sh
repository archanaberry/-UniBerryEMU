#!/bin/bash

################################################################
#                                                              #
#  -------------------UniBerry EMU Engine-------------------   #
#  Created by: Archana Berry                                   #
#  Build script: Bash                                          #
#  Version resource: v0.001_alpha                              #
#  File: build.sh                                              #
#  Type: script[build]                                         #
#  Desc: Build automation for UniBerry EMU Engine              #
#                                                              #
#  ----------------------------------------------------------  #
#                                                              #
#  ---- This script automates compilation with dependency  ----#
#  ---- checking, library installation, and optimization.  ----#
#                                                              #
################################################################
#                                                              #
#  Patiently awaiting the release of UniBerryEMU.c             #
#                                                              #
################################################################

#!/bin/bash

set -e

echo "=========================================================="
echo "    UniBerry EMU Engine - Universal Binary Execution"
echo "    Version: v0.001_alpha | Creator: Archana Berry"
echo "=========================================================="
echo ""

# Pastikan pkg-config menemukan library di /usr/local
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/lib/pkgconfig:$PKG_CONFIG_PATH

# Cek dependency
echo "[*] Checking dependencies..."
for lib in unicorn capstone keystone; do
    if ! pkg-config --exists $lib; then
        echo "✗ Missing: $lib"
        echo "  Install / build $lib terlebih dahulu"
        exit 1
    fi
    echo "✓ $lib $(pkg-config --modversion $lib)"
done
echo ""

mkdir -p target

echo "[*] Compiling UniBerry EMU Engine..."
echo ""

gcc -Wall -Wextra -O2 -g \
    ubemu.c \
    arch/arm.c \
    arch/8086.c \
    target/elf.c \
    target/pm.c \
    target/macho.c \
    $(pkg-config --cflags unicorn capstone keystone) \
    $(pkg-config --libs unicorn capstone keystone) \
    -lpthread -lm \
    -o uniberryemu

echo ""
echo "✓ Compilation successful!"
echo ""
echo "Binary : uniberryemu"
echo "Size   : $(du -h uniberryemu | cut -f1)"
echo ""

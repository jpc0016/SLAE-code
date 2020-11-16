#!/bin/bash

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm

echo '[+] Linking ... '
# ld -z execstack -o $1 $1.o
# For targeting 32-bit from 64-bit system:
ld -z execstack -N -m elf_i386 -o $1 $1.o

echo '[+] Done!'

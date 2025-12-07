// MIT License

// Copyright (c) 2025 Oblivionsage

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

// src/main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "elf_parser.h"

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <elf-file> [addr]\n", argv[0]);
        return 1;
    }

    ElfFile elf;
    if (elf_parse_file(argv[1], &elf) != 0)
        return 1;

    elf_print_header(&elf);
    elf_print_phdrs(&elf);
    elf_print_sections(&elf);
    elf_print_dynsym(&elf);
    elf_print_symtab(&elf);

    if (argc == 3) {
        uint64_t addr;
        if (strncmp(argv[2], "0x", 2) == 0 || strncmp(argv[2], "0X", 2) == 0)
            addr = strtoull(argv[2], NULL, 16);
        else
            addr = strtoull(argv[2], NULL, 10);

        elf_resolve_addr(&elf, addr);
    }

    elf_free(&elf);
    return 0;
}

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

// src/main.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "elf_parser.h"
#include "repl.h"
#include "colors.h"

extern int use_colors;

int main(int argc, char **argv)
{
    use_colors = isatty(STDOUT_FILENO);
    
    if (argc == 1) {
        repl_run();
        return 0;
    }
    
    if (argc > 3) {
        fprintf(stderr, "usage: %s [elf-file] [addr]\n", argv[0]);
        return 1;
    }

    ElfFile elf;
    if (elf_parse_file(argv[1], &elf) != 0)
        return 1;

    if (argc == 2) {
        elf_print_header(&elf);
        elf_print_phdrs(&elf);
        elf_print_sections(&elf);
    } else {
        uint64_t addr = strtoull(argv[2], NULL, 0);
        elf_resolve_addr(&elf, addr);
    }

    elf_free(&elf);
    return 0;
}

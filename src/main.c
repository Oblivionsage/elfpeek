#include <stdio.h>
#include "elf_parser.h"

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <elf-file>\n", argv[0]);
        return 1;
    }

    ElfFile elf;
    if (elf_parse_file(argv[1], &elf) != 0)
        return 1;

    elf_print_header(&elf);
    elf_print_phdrs(&elf);
    elf_print_sections(&elf);

    elf_free(&elf);
    return 0;
}

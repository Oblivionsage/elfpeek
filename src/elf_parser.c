#include "elf_parser.h"
#include "colors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int use_colors = 1;

int elf_parse_file(const char *path, ElfFile *out)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "%serror:%s cannot open '%s'\n",
                COL(CLR_RED), COL(CLR_RST), path);
        return -1;
    }

    memset(out, 0, sizeof(*out));

    if (fread(&out->ehdr, sizeof(out->ehdr), 1, fp) != 1) {
        fprintf(stderr, "%serror:%s failed to read elf header\n",
                COL(CLR_RED), COL(CLR_RST));
        fclose(fp);
        return -1;
    }

    // magic check
    if (memcmp(out->ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "%serror:%s not an ELF file\n",
                COL(CLR_RED), COL(CLR_RST));
        fclose(fp);
        return -1;
    }

    // 64-bit check
    if (out->ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "%serror:%s only ELF64 supported\n",
                COL(CLR_RED), COL(CLR_RST));
        fclose(fp);
        return -1;
    }

    // little endian check
    if (out->ehdr.e_ident[EI_DATA] != ELFDATA2LSB) {
        fprintf(stderr, "%swarn:%s big-endian, results may be wrong\n",
                COL(CLR_YEL), COL(CLR_RST));
    }

    fclose(fp);
    return 0;
}

void elf_print_header(const ElfFile *elf)
{
    (void)elf;
}

void elf_print_sections(const ElfFile *elf)
{
    (void)elf;
}

void elf_free(ElfFile *elf)
{
    free(elf->sections);
    free(elf->shstrtab);
}

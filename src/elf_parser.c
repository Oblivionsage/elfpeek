#include "elf_parser.h"
#include "colors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int use_colors = 1;

static const char *elf_type_str(uint16_t type)
{
    switch (type) {
    case ET_NONE: return "NONE";
    case ET_REL:  return "REL (Relocatable)";
    case ET_EXEC: return "EXEC (Executable)";
    case ET_DYN:  return "DYN (Shared object)";
    case ET_CORE: return "CORE (Core dump)";
    default:      return "Unknown";
    }
}

static const char *elf_machine_str(uint16_t machine)
{
    switch (machine) {
    case EM_X86_64:  return "x86_64";
    case EM_386:     return "i386";
    case EM_ARM:     return "ARM";
    case EM_AARCH64: return "AArch64";
    case EM_RISCV:   return "RISC-V";
    default:         return "Unknown";
    }
}

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
    const Elf64_Ehdr *e = &elf->ehdr;

    printf("\n%s[ELF HEADER]%s\n", COL(CLR_CYN), COL(CLR_RST));
    printf("  Type        : %s\n", elf_type_str(e->e_type));
    printf("  Machine     : %s\n", elf_machine_str(e->e_machine));
    printf("  Entry       : 0x%016lx\n", (unsigned long)e->e_entry);
    printf("  PHDR offset : 0x%08lx (%u entries)\n",
           (unsigned long)e->e_phoff, e->e_phnum);
    printf("  SHDR offset : 0x%08lx (%u entries)\n",
           (unsigned long)e->e_shoff, e->e_shnum);
    printf("  SHSTR index : %u\n", e->e_shstrndx);
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

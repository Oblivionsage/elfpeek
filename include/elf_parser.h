#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <elf.h>
#include <stdint.h>

typedef struct {
    Elf64_Ehdr ehdr;
    Elf64_Phdr *phdrs;
    Elf64_Shdr *sections;
    char *shstrtab;
    uint16_t phnum;
    uint16_t shnum;
    int entry_sec;
} ElfFile;

int elf_parse_file(const char *path, ElfFile *out);
void elf_print_header(const ElfFile *elf);
void elf_print_phdrs(const ElfFile *elf);
void elf_print_sections(const ElfFile *elf);
int elf_print_dynsym(const ElfFile *elf, const char *path);
void elf_resolve_addr(const ElfFile *elf, uint64_t addr);
void elf_free(ElfFile *elf);

#endif

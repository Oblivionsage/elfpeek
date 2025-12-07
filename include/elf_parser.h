// include/elf_parser.h
#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <elf.h>
#include <stdint.h>
#include <stddef.h>

typedef enum {
    SYM_SRC_DYNSYM,
    SYM_SRC_SYMTAB
} SymbolSource;

typedef struct {
    uint64_t value;
    uint64_t size;
    unsigned char type;
    unsigned char bind;
    uint16_t shndx;
    const char *name;
    SymbolSource source;
} ElfSymbolInfo;

typedef struct {
    // we store everything as 64-bit internally, convert from 32-bit if needed
    Elf64_Ehdr ehdr;
    Elf64_Phdr *phdrs;
    Elf64_Shdr *sections;
    char *shstrtab;
    uint16_t phnum;
    uint16_t shnum;
    int entry_sec;

    int is32;   // ELF32 file
    int swap;   // needs byte swapping (big-endian)

    ElfSymbolInfo *dynsyms;
    size_t dynsym_count;
    char *dynstr;

    ElfSymbolInfo *symtab;
    size_t symtab_count;
    char *strtab;
} ElfFile;

int elf_parse_file(const char *path, ElfFile *out);
void elf_print_header(const ElfFile *elf);
void elf_print_phdrs(const ElfFile *elf);
void elf_print_sections(const ElfFile *elf);
void elf_print_dynsym(const ElfFile *elf);
void elf_print_symtab(const ElfFile *elf);
void elf_resolve_addr(const ElfFile *elf, uint64_t addr);
void elf_free(ElfFile *elf);

#endif

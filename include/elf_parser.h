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
    Elf64_Ehdr ehdr;
    Elf64_Phdr *phdrs;
    Elf64_Shdr *sections;
    char *shstrtab;

    uint16_t phnum;
    uint16_t shnum;
    int entry_sec;
    int is32;
    int swap;

    ElfSymbolInfo *dynsyms;
    size_t dynsym_count;
    char *dynstr;

    ElfSymbolInfo *symtab;
    size_t symtab_count;
    char *strtab;

    // for hexdump - we keep file path to re-read
    char *path;
} ElfFile;

int elf_parse_file(const char *path, ElfFile *out);
void elf_print_header(const ElfFile *elf);
void elf_print_phdrs(const ElfFile *elf);
void elf_print_sections(const ElfFile *elf);
void elf_print_dynsym(const ElfFile *elf);
void elf_print_symtab(const ElfFile *elf);
void elf_print_entry(const ElfFile *elf);
void elf_resolve_addr(const ElfFile *elf, uint64_t addr);
void elf_free(ElfFile *elf);

// new for repl
int elf_find_section(const ElfFile *elf, const char *name, uint64_t *off, uint64_t *size);
void elf_hexdump(const ElfFile *elf, uint64_t offset, size_t len);

#endif

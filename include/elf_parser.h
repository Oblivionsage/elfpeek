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

    // dynsym
    ElfSymbolInfo *dynsyms;
    size_t dynsym_count;
    char *dynstr;

    // symtab
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

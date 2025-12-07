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

// src/elf_parser.c
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

static const char *sh_type_str(uint32_t type)
{
    switch (type) {
    case SHT_NULL:     return "NULL";
    case SHT_PROGBITS: return "PROGBITS";
    case SHT_SYMTAB:   return "SYMTAB";
    case SHT_STRTAB:   return "STRTAB";
    case SHT_RELA:     return "RELA";
    case SHT_HASH:     return "HASH";
    case SHT_DYNAMIC:  return "DYNAMIC";
    case SHT_NOTE:     return "NOTE";
    case SHT_NOBITS:   return "NOBITS";
    case SHT_REL:      return "REL";
    case SHT_DYNSYM:   return "DYNSYM";
    case SHT_INIT_ARRAY:  return "INIT_ARRAY";
    case SHT_FINI_ARRAY:  return "FINI_ARRAY";
    case SHT_GNU_HASH: return "GNU_HASH";
    case SHT_GNU_versym:  return "VERSYM";
    case SHT_GNU_verneed: return "VERNEED";
    default:           return "UNKNOWN";
    }
}

static const char *ph_type_str(uint32_t type)
{
    switch (type) {
    case PT_NULL:    return "NULL";
    case PT_LOAD:    return "LOAD";
    case PT_DYNAMIC: return "DYNAMIC";
    case PT_INTERP:  return "INTERP";
    case PT_NOTE:    return "NOTE";
    case PT_PHDR:    return "PHDR";
    case PT_TLS:     return "TLS";
    case PT_GNU_EH_FRAME: return "GNU_EH_FRAME";
    case PT_GNU_STACK:    return "GNU_STACK";
    case PT_GNU_RELRO:    return "GNU_RELRO";
    case PT_GNU_PROPERTY: return "GNU_PROPERTY";
    default:         return "UNKNOWN";
    }
}

static const char *sym_type_str(unsigned char type)
{
    switch (type) {
    case STT_NOTYPE:  return "NOTYPE";
    case STT_OBJECT:  return "OBJECT";
    case STT_FUNC:    return "FUNC";
    case STT_SECTION: return "SECTION";
    case STT_FILE:    return "FILE";
    default:          return "OTHER";
    }
}

static void format_flags(uint64_t flags, char *buf, size_t len)
{
    buf[0] = '\0';
    if (flags & SHF_WRITE)     strncat(buf, "W", len - 1);
    if (flags & SHF_ALLOC)     strncat(buf, "A", len - strlen(buf) - 1);
    if (flags & SHF_EXECINSTR) strncat(buf, "X", len - strlen(buf) - 1);
}

static void format_phdr_flags(uint32_t flags, char *buf)
{
    buf[0] = (flags & PF_R) ? 'R' : ' ';
    buf[1] = (flags & PF_W) ? 'W' : ' ';
    buf[2] = (flags & PF_X) ? 'X' : ' ';
    buf[3] = '\0';
}

// load symbols from a symbol table section
static int load_symbols(FILE *fp, Elf64_Shdr *symtab_sec, Elf64_Shdr *strtab_sec,
                        ElfSymbolInfo **out_syms, size_t *out_count, 
                        char **out_strtab, SymbolSource source)
{
    size_t sym_count = symtab_sec->sh_size / sizeof(Elf64_Sym);
    if (sym_count == 0)
        return 0;

    // read string table
    char *strtab = malloc(strtab_sec->sh_size);
    if (!strtab)
        return -1;
    
    fseek(fp, strtab_sec->sh_offset, SEEK_SET);
    if (fread(strtab, 1, strtab_sec->sh_size, fp) != strtab_sec->sh_size) {
        free(strtab);
        return -1;
    }

    // read symbol entries
    Elf64_Sym *raw_syms = malloc(symtab_sec->sh_size);
    if (!raw_syms) {
        free(strtab);
        return -1;
    }
    
    fseek(fp, symtab_sec->sh_offset, SEEK_SET);
    if (fread(raw_syms, sizeof(Elf64_Sym), sym_count, fp) != sym_count) {
        free(raw_syms);
        free(strtab);
        return -1;
    }

    // convert to our format
    ElfSymbolInfo *syms = malloc(sym_count * sizeof(ElfSymbolInfo));
    if (!syms) {
        free(raw_syms);
        free(strtab);
        return -1;
    }

    for (size_t i = 0; i < sym_count; i++) {
        Elf64_Sym *s = &raw_syms[i];
        syms[i].value = s->st_value;
        syms[i].size = s->st_size;
        syms[i].type = ELF64_ST_TYPE(s->st_info);
        syms[i].bind = ELF64_ST_BIND(s->st_info);
        syms[i].shndx = s->st_shndx;
        syms[i].source = source;
        
        if (s->st_name < strtab_sec->sh_size)
            syms[i].name = strtab + s->st_name;
        else
            syms[i].name = "";
    }

    free(raw_syms);
    *out_syms = syms;
    *out_count = sym_count;
    *out_strtab = strtab;
    return 0;
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
    out->entry_sec = -1;

    if (fread(&out->ehdr, sizeof(out->ehdr), 1, fp) != 1) {
        fprintf(stderr, "%serror:%s failed to read elf header\n",
                COL(CLR_RED), COL(CLR_RST));
        fclose(fp);
        return -1;
    }

    if (memcmp(out->ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "%serror:%s not an ELF file\n",
                COL(CLR_RED), COL(CLR_RST));
        fclose(fp);
        return -1;
    }

    if (out->ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "%serror:%s only ELF64 supported\n",
                COL(CLR_RED), COL(CLR_RST));
        fclose(fp);
        return -1;
    }

    if (out->ehdr.e_ident[EI_DATA] != ELFDATA2LSB) {
        fprintf(stderr, "%swarn:%s big-endian, results may be wrong\n",
                COL(CLR_YEL), COL(CLR_RST));
    }

    // program headers
    out->phnum = out->ehdr.e_phnum;
    if (out->phnum > 0) {
        out->phdrs = malloc(out->phnum * sizeof(Elf64_Phdr));
        if (!out->phdrs) {
            fprintf(stderr, "%serror:%s malloc failed\n",
                    COL(CLR_RED), COL(CLR_RST));
            fclose(fp);
            return -1;
        }
        fseek(fp, out->ehdr.e_phoff, SEEK_SET);
        if (fread(out->phdrs, sizeof(Elf64_Phdr), out->phnum, fp) != out->phnum) {
            fprintf(stderr, "%serror:%s truncated program headers\n",
                    COL(CLR_RED), COL(CLR_RST));
            free(out->phdrs);
            fclose(fp);
            return -1;
        }
    }

    // section headers
    out->shnum = out->ehdr.e_shnum;
    if (out->shnum == 0) {
        fclose(fp);
        return 0;
    }

    size_t sh_size = out->shnum * sizeof(Elf64_Shdr);
    out->sections = malloc(sh_size);
    if (!out->sections) {
        fprintf(stderr, "%serror:%s malloc failed\n",
                COL(CLR_RED), COL(CLR_RST));
        fclose(fp);
        return -1;
    }

    fseek(fp, out->ehdr.e_shoff, SEEK_SET);
    if (fread(out->sections, sizeof(Elf64_Shdr), out->shnum, fp) != out->shnum) {
        fprintf(stderr, "%serror:%s truncated section headers\n",
                COL(CLR_RED), COL(CLR_RST));
        free(out->sections);
        fclose(fp);
        return -1;
    }

    // shstrtab
    uint16_t stridx = out->ehdr.e_shstrndx;
    if (stridx < out->shnum && stridx != SHN_UNDEF) {
        Elf64_Shdr *strsec = &out->sections[stridx];
        out->shstrtab = malloc(strsec->sh_size);
        if (out->shstrtab) {
            fseek(fp, strsec->sh_offset, SEEK_SET);
            if (fread(out->shstrtab, 1, strsec->sh_size, fp) != strsec->sh_size) {
                free(out->shstrtab);
                out->shstrtab = NULL;
            }
        }
    }

    // find entry section
    uint64_t entry = out->ehdr.e_entry;
    for (uint16_t i = 0; i < out->shnum; i++) {
        Elf64_Shdr *s = &out->sections[i];
        if (s->sh_addr && entry >= s->sh_addr && entry < s->sh_addr + s->sh_size) {
            out->entry_sec = i;
            break;
        }
    }

    // load .dynsym
    for (uint16_t i = 0; i < out->shnum; i++) {
        if (out->sections[i].sh_type == SHT_DYNSYM) {
            uint32_t link = out->sections[i].sh_link;
            if (link < out->shnum) {
                load_symbols(fp, &out->sections[i], &out->sections[link],
                            &out->dynsyms, &out->dynsym_count, &out->dynstr,
                            SYM_SRC_DYNSYM);
            }
            break;
        }
    }

    // load .symtab
    for (uint16_t i = 0; i < out->shnum; i++) {
        if (out->sections[i].sh_type == SHT_SYMTAB) {
            uint32_t link = out->sections[i].sh_link;
            if (link < out->shnum) {
                load_symbols(fp, &out->sections[i], &out->sections[link],
                            &out->symtab, &out->symtab_count, &out->strtab,
                            SYM_SRC_SYMTAB);
            }
            break;
        }
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

    if (elf->entry_sec >= 0 && elf->shstrtab) {
        const char *name = elf->shstrtab + elf->sections[elf->entry_sec].sh_name;
        printf("  Entry       : 0x%016lx  (in %s)\n", (unsigned long)e->e_entry, name);
    } else {
        printf("  Entry       : 0x%016lx\n", (unsigned long)e->e_entry);
    }

    printf("  PHDR offset : 0x%08lx (%u entries)\n",
           (unsigned long)e->e_phoff, e->e_phnum);
    printf("  SHDR offset : 0x%08lx (%u entries)\n",
           (unsigned long)e->e_shoff, e->e_shnum);
    printf("  SHSTR index : %u\n", e->e_shstrndx);
}

void elf_print_phdrs(const ElfFile *elf)
{
    if (elf->phnum == 0)
        return;

    printf("\n%s[PROGRAM HEADERS]%s\n", COL(CLR_CYN), COL(CLR_RST));

    for (uint16_t i = 0; i < elf->phnum; i++) {
        const Elf64_Phdr *p = &elf->phdrs[i];
        char flags[4];
        format_phdr_flags(p->p_flags, flags);

        printf("  [%2u] %-12s  %s  OFF=0x%06lx  VADDR=0x%016lx  FILESZ=0x%06lx  MEMSZ=0x%06lx\n",
               i, ph_type_str(p->p_type), flags,
               (unsigned long)p->p_offset,
               (unsigned long)p->p_vaddr,
               (unsigned long)p->p_filesz,
               (unsigned long)p->p_memsz);
    }
}

void elf_print_sections(const ElfFile *elf)
{
    if (elf->shnum == 0) {
        printf("\n  (no sections)\n");
        return;
    }

    printf("\n%s[SECTIONS]%s\n", COL(CLR_CYN), COL(CLR_RST));

    for (uint16_t i = 0; i < elf->shnum; i++) {
        const Elf64_Shdr *s = &elf->sections[i];

        const char *name = "";
        if (elf->shstrtab && s->sh_name < elf->sections[elf->ehdr.e_shstrndx].sh_size)
            name = elf->shstrtab + s->sh_name;

        char flags[8];
        format_flags(s->sh_flags, flags, sizeof(flags));

        const char *col = "";
        if (s->sh_flags & SHF_EXECINSTR)
            col = COL(CLR_GRN);
        else if (s->sh_flags & SHF_WRITE)
            col = COL(CLR_YEL);
        else if (s->sh_flags & SHF_ALLOC)
            col = COL(CLR_CYN);

        printf("  %s[%2u] %-18s%s  TYPE=%-10s", col, i, name, COL(CLR_RST), sh_type_str(s->sh_type));

        if (flags[0])
            printf("  FLAGS=%-3s", flags);
        if (s->sh_addr)
            printf("  ADDR=0x%08lx", (unsigned long)s->sh_addr);
        if (s->sh_offset)
            printf("  OFF=0x%06lx", (unsigned long)s->sh_offset);
        if (s->sh_size)
            printf("  SIZE=0x%lx", (unsigned long)s->sh_size);

        if (i == elf->entry_sec)
            printf("  %s<-- entry%s", COL(CLR_GRN), COL(CLR_RST));

        printf("\n");
    }
}

static void print_symbol_table(const ElfSymbolInfo *syms, size_t count, const char *title)
{
    printf("\n%s[%s]%s\n", COL(CLR_CYN), title, COL(CLR_RST));

    for (size_t i = 1; i < count; i++) {
        const ElfSymbolInfo *s = &syms[i];
        
        // skip useless entries
        if (s->type != STT_FUNC && s->type != STT_OBJECT)
            continue;

        printf("  %016lx  %-6s  %4lu  %s\n",
               (unsigned long)s->value,
               sym_type_str(s->type),
               (unsigned long)s->size,
               s->name);
    }
}

void elf_print_dynsym(const ElfFile *elf)
{
    if (!elf->dynsyms || elf->dynsym_count == 0) {
        fprintf(stderr, "  %swarn:%s no .dynsym section\n", COL(CLR_YEL), COL(CLR_RST));
        return;
    }
    print_symbol_table(elf->dynsyms, elf->dynsym_count, "DYNSYM");
}

void elf_print_symtab(const ElfFile *elf)
{
    if (!elf->symtab || elf->symtab_count == 0)
        return;
    print_symbol_table(elf->symtab, elf->symtab_count, "SYMTAB");
}

// find best matching symbol for addr
static const ElfSymbolInfo *find_symbol_for_addr(const ElfFile *elf, uint64_t addr)
{
    const ElfSymbolInfo *best = NULL;
    uint64_t best_dist = UINT64_MAX;

    // check symtab first (higher priority)
    for (size_t i = 1; i < elf->symtab_count; i++) {
        const ElfSymbolInfo *s = &elf->symtab[i];
        
        if (s->value == 0 || !s->name || !s->name[0])
            continue;
        if (s->type != STT_FUNC && s->type != STT_OBJECT)
            continue;
        if (s->value > addr)
            continue;

        // exact match or within bounds
        if (s->size > 0 && addr < s->value + s->size) {
            return s;
        }

        uint64_t dist = addr - s->value;
        if (dist < best_dist) {
            best_dist = dist;
            best = s;
        }
    }

    // then check dynsym
    for (size_t i = 1; i < elf->dynsym_count; i++) {
        const ElfSymbolInfo *s = &elf->dynsyms[i];
        
        if (s->value == 0 || !s->name || !s->name[0])
            continue;
        if (s->type != STT_FUNC && s->type != STT_OBJECT)
            continue;
        if (s->value > addr)
            continue;

        // exact match or within bounds
        if (s->size > 0 && addr < s->value + s->size) {
            // only use dynsym if we don't have a symtab match
            if (!best || best->source != SYM_SRC_SYMTAB)
                return s;
        }

        uint64_t dist = addr - s->value;
        if (dist < best_dist) {
            best_dist = dist;
            best = s;
        }
    }

    return best;
}

void elf_resolve_addr(const ElfFile *elf, uint64_t addr)
{
    printf("\n%s[ADDR]%s\n", COL(CLR_CYN), COL(CLR_RST));
    printf("  Address  : 0x%016lx\n", (unsigned long)addr);

    // find segment
    int seg_idx = -1;
    for (uint16_t i = 0; i < elf->phnum; i++) {
        const Elf64_Phdr *p = &elf->phdrs[i];
        if (p->p_type == PT_LOAD && addr >= p->p_vaddr && addr < p->p_vaddr + p->p_memsz) {
            seg_idx = i;
            break;
        }
    }

    if (seg_idx >= 0) {
        const Elf64_Phdr *p = &elf->phdrs[seg_idx];
        char flags[4];
        format_phdr_flags(p->p_flags, flags);
        printf("  Segment  : [%2d] %-12s  %s  VADDR=0x%016lx\n",
               seg_idx, ph_type_str(p->p_type), flags, (unsigned long)p->p_vaddr);

        uint64_t file_off = p->p_offset + (addr - p->p_vaddr);
        printf("  File off : 0x%08lx\n", (unsigned long)file_off);
    } else {
        printf("  Segment  : (not in any PT_LOAD segment)\n");
    }

    // find section
    int sec_idx = -1;
    for (uint16_t i = 0; i < elf->shnum; i++) {
        const Elf64_Shdr *s = &elf->sections[i];
        if ((s->sh_flags & SHF_ALLOC) && addr >= s->sh_addr && addr < s->sh_addr + s->sh_size) {
            sec_idx = i;
            break;
        }
    }

    if (sec_idx >= 0 && elf->shstrtab) {
        const char *name = elf->shstrtab + elf->sections[sec_idx].sh_name;
        printf("  Section  : [%2d] %s\n", sec_idx, name);
    } else {
        printf("  Section  : (no matching section)\n");
    }

    // find symbol
    const ElfSymbolInfo *sym = find_symbol_for_addr(elf, addr);
    if (sym) {
        uint64_t offset = addr - sym->value;
        const char *src = (sym->source == SYM_SRC_SYMTAB) ? "SYMTAB" : "DYNSYM";
        
        if (offset == 0) {
            printf("  Symbol   : %s (%s, %s)\n", sym->name, sym_type_str(sym->type), src);
        } else {
            printf("  Symbol   : %s+0x%lx (%s, %s)\n", 
                   sym->name, (unsigned long)offset, sym_type_str(sym->type), src);
        }
    } else {
        printf("  Symbol   : (no matching symbol)\n");
    }
}

void elf_free(ElfFile *elf)
{
    free(elf->phdrs);
    free(elf->sections);
    free(elf->shstrtab);
    free(elf->dynsyms);
    free(elf->dynstr);
    free(elf->symtab);
    free(elf->strtab);
}

// src/elf_parser.c
#define _GNU_SOURCE
#include "elf_parser.h"
#include "colors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int use_colors = 1;

static inline uint16_t bswap16(uint16_t x) {
    return (x >> 8) | (x << 8);
}

static inline uint32_t bswap32(uint32_t x) {
    return ((x >> 24) & 0xff) | ((x >> 8) & 0xff00) |
           ((x << 8) & 0xff0000) | ((x << 24) & 0xff000000);
}

static inline uint64_t bswap64(uint64_t x) {
    return ((uint64_t)bswap32(x & 0xffffffff) << 32) | bswap32(x >> 32);
}

#define SWAP16(elf, x) ((elf)->swap ? bswap16(x) : (x))
#define SWAP32(elf, x) ((elf)->swap ? bswap32(x) : (x))
#define SWAP64(elf, x) ((elf)->swap ? bswap64(x) : (x))

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
    case EM_MIPS:    return "MIPS";
    case EM_PPC:     return "PowerPC";
    case EM_PPC64:   return "PowerPC64";
    case EM_SPARC:   return "SPARC";
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

static int read_ehdr32(FILE *fp, ElfFile *elf)
{
    Elf32_Ehdr e32;
    rewind(fp);
    if (fread(&e32, sizeof(e32), 1, fp) != 1)
        return -1;

    memcpy(elf->ehdr.e_ident, e32.e_ident, EI_NIDENT);
    
    elf->ehdr.e_type      = SWAP16(elf, e32.e_type);
    elf->ehdr.e_machine   = SWAP16(elf, e32.e_machine);
    elf->ehdr.e_version   = SWAP32(elf, e32.e_version);
    elf->ehdr.e_entry     = SWAP32(elf, e32.e_entry);
    elf->ehdr.e_phoff     = SWAP32(elf, e32.e_phoff);
    elf->ehdr.e_shoff     = SWAP32(elf, e32.e_shoff);
    elf->ehdr.e_flags     = SWAP32(elf, e32.e_flags);
    elf->ehdr.e_ehsize    = SWAP16(elf, e32.e_ehsize);
    elf->ehdr.e_phentsize = SWAP16(elf, e32.e_phentsize);
    elf->ehdr.e_phnum     = SWAP16(elf, e32.e_phnum);
    elf->ehdr.e_shentsize = SWAP16(elf, e32.e_shentsize);
    elf->ehdr.e_shnum     = SWAP16(elf, e32.e_shnum);
    elf->ehdr.e_shstrndx  = SWAP16(elf, e32.e_shstrndx);
    
    return 0;
}

static int read_ehdr64(FILE *fp, ElfFile *elf)
{
    rewind(fp);
    if (fread(&elf->ehdr, sizeof(elf->ehdr), 1, fp) != 1)
        return -1;

    if (elf->swap) {
        elf->ehdr.e_type      = bswap16(elf->ehdr.e_type);
        elf->ehdr.e_machine   = bswap16(elf->ehdr.e_machine);
        elf->ehdr.e_version   = bswap32(elf->ehdr.e_version);
        elf->ehdr.e_entry     = bswap64(elf->ehdr.e_entry);
        elf->ehdr.e_phoff     = bswap64(elf->ehdr.e_phoff);
        elf->ehdr.e_shoff     = bswap64(elf->ehdr.e_shoff);
        elf->ehdr.e_flags     = bswap32(elf->ehdr.e_flags);
        elf->ehdr.e_ehsize    = bswap16(elf->ehdr.e_ehsize);
        elf->ehdr.e_phentsize = bswap16(elf->ehdr.e_phentsize);
        elf->ehdr.e_phnum     = bswap16(elf->ehdr.e_phnum);
        elf->ehdr.e_shentsize = bswap16(elf->ehdr.e_shentsize);
        elf->ehdr.e_shnum     = bswap16(elf->ehdr.e_shnum);
        elf->ehdr.e_shstrndx  = bswap16(elf->ehdr.e_shstrndx);
    }
    return 0;
}

static int read_phdrs(FILE *fp, ElfFile *elf)
{
    elf->phnum = elf->ehdr.e_phnum;
    if (elf->phnum == 0)
        return 0;

    elf->phdrs = malloc(elf->phnum * sizeof(Elf64_Phdr));
    if (!elf->phdrs)
        return -1;

    fseek(fp, elf->ehdr.e_phoff, SEEK_SET);

    if (elf->is32) {
        for (uint16_t i = 0; i < elf->phnum; i++) {
            Elf32_Phdr p32;
            if (fread(&p32, sizeof(p32), 1, fp) != 1)
                return -1;
            elf->phdrs[i].p_type   = SWAP32(elf, p32.p_type);
            elf->phdrs[i].p_flags  = SWAP32(elf, p32.p_flags);
            elf->phdrs[i].p_offset = SWAP32(elf, p32.p_offset);
            elf->phdrs[i].p_vaddr  = SWAP32(elf, p32.p_vaddr);
            elf->phdrs[i].p_paddr  = SWAP32(elf, p32.p_paddr);
            elf->phdrs[i].p_filesz = SWAP32(elf, p32.p_filesz);
            elf->phdrs[i].p_memsz  = SWAP32(elf, p32.p_memsz);
            elf->phdrs[i].p_align  = SWAP32(elf, p32.p_align);
        }
    } else {
        if (fread(elf->phdrs, sizeof(Elf64_Phdr), elf->phnum, fp) != elf->phnum)
            return -1;
        if (elf->swap) {
            for (uint16_t i = 0; i < elf->phnum; i++) {
                Elf64_Phdr *p = &elf->phdrs[i];
                p->p_type   = bswap32(p->p_type);
                p->p_flags  = bswap32(p->p_flags);
                p->p_offset = bswap64(p->p_offset);
                p->p_vaddr  = bswap64(p->p_vaddr);
                p->p_paddr  = bswap64(p->p_paddr);
                p->p_filesz = bswap64(p->p_filesz);
                p->p_memsz  = bswap64(p->p_memsz);
                p->p_align  = bswap64(p->p_align);
            }
        }
    }
    return 0;
}

static int read_shdrs(FILE *fp, ElfFile *elf)
{
    elf->shnum = elf->ehdr.e_shnum;
    if (elf->shnum == 0)
        return 0;

    elf->sections = malloc(elf->shnum * sizeof(Elf64_Shdr));
    if (!elf->sections)
        return -1;

    fseek(fp, elf->ehdr.e_shoff, SEEK_SET);

    if (elf->is32) {
        for (uint16_t i = 0; i < elf->shnum; i++) {
            Elf32_Shdr s32;
            if (fread(&s32, sizeof(s32), 1, fp) != 1)
                return -1;
            elf->sections[i].sh_name      = SWAP32(elf, s32.sh_name);
            elf->sections[i].sh_type      = SWAP32(elf, s32.sh_type);
            elf->sections[i].sh_flags     = SWAP32(elf, s32.sh_flags);
            elf->sections[i].sh_addr      = SWAP32(elf, s32.sh_addr);
            elf->sections[i].sh_offset    = SWAP32(elf, s32.sh_offset);
            elf->sections[i].sh_size      = SWAP32(elf, s32.sh_size);
            elf->sections[i].sh_link      = SWAP32(elf, s32.sh_link);
            elf->sections[i].sh_info      = SWAP32(elf, s32.sh_info);
            elf->sections[i].sh_addralign = SWAP32(elf, s32.sh_addralign);
            elf->sections[i].sh_entsize   = SWAP32(elf, s32.sh_entsize);
        }
    } else {
        if (fread(elf->sections, sizeof(Elf64_Shdr), elf->shnum, fp) != elf->shnum)
            return -1;
        if (elf->swap) {
            for (uint16_t i = 0; i < elf->shnum; i++) {
                Elf64_Shdr *s = &elf->sections[i];
                s->sh_name      = bswap32(s->sh_name);
                s->sh_type      = bswap32(s->sh_type);
                s->sh_flags     = bswap64(s->sh_flags);
                s->sh_addr      = bswap64(s->sh_addr);
                s->sh_offset    = bswap64(s->sh_offset);
                s->sh_size      = bswap64(s->sh_size);
                s->sh_link      = bswap32(s->sh_link);
                s->sh_info      = bswap32(s->sh_info);
                s->sh_addralign = bswap64(s->sh_addralign);
                s->sh_entsize   = bswap64(s->sh_entsize);
            }
        }
    }
    return 0;
}

static int load_symbols(FILE *fp, ElfFile *elf, Elf64_Shdr *symtab_sec, Elf64_Shdr *strtab_sec,
                        ElfSymbolInfo **out_syms, size_t *out_count, 
                        char **out_strtab, SymbolSource source)
{
    size_t entry_size = elf->is32 ? sizeof(Elf32_Sym) : sizeof(Elf64_Sym);
    size_t sym_count = symtab_sec->sh_size / entry_size;
    if (sym_count == 0)
        return 0;

    char *strtab = malloc(strtab_sec->sh_size);
    if (!strtab)
        return -1;
    
    fseek(fp, strtab_sec->sh_offset, SEEK_SET);
    if (fread(strtab, 1, strtab_sec->sh_size, fp) != strtab_sec->sh_size) {
        free(strtab);
        return -1;
    }

    ElfSymbolInfo *syms = malloc(sym_count * sizeof(ElfSymbolInfo));
    if (!syms) {
        free(strtab);
        return -1;
    }

    fseek(fp, symtab_sec->sh_offset, SEEK_SET);

    for (size_t i = 0; i < sym_count; i++) {
        uint32_t st_name;
        uint64_t st_value, st_size;
        unsigned char st_info;
        uint16_t st_shndx;

        if (elf->is32) {
            Elf32_Sym s32;
            if (fread(&s32, sizeof(s32), 1, fp) != 1) {
                free(syms);
                free(strtab);
                return -1;
            }
            st_name  = SWAP32(elf, s32.st_name);
            st_value = SWAP32(elf, s32.st_value);
            st_size  = SWAP32(elf, s32.st_size);
            st_info  = s32.st_info;
            st_shndx = SWAP16(elf, s32.st_shndx);
        } else {
            Elf64_Sym s64;
            if (fread(&s64, sizeof(s64), 1, fp) != 1) {
                free(syms);
                free(strtab);
                return -1;
            }
            st_name  = SWAP32(elf, s64.st_name);
            st_value = SWAP64(elf, s64.st_value);
            st_size  = SWAP64(elf, s64.st_size);
            st_info  = s64.st_info;
            st_shndx = SWAP16(elf, s64.st_shndx);
        }

        syms[i].value  = st_value;
        syms[i].size   = st_size;
        syms[i].type   = ELF64_ST_TYPE(st_info);
        syms[i].bind   = ELF64_ST_BIND(st_info);
        syms[i].shndx  = st_shndx;
        syms[i].source = source;
        
        if (st_name < strtab_sec->sh_size)
            syms[i].name = strtab + st_name;
        else
            syms[i].name = "";
    }

    *out_syms = syms;
    *out_count = sym_count;
    *out_strtab = strtab;
    return 0;
}

int elf_parse_file(const char *path, ElfFile *out)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "%serror:%s cannot open '%s'\n", COL(CLR_RED), COL(CLR_RST), path);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->entry_sec = -1;

    unsigned char ident[EI_NIDENT];
    if (fread(ident, 1, EI_NIDENT, fp) != EI_NIDENT) {
        fprintf(stderr, "%serror:%s failed to read elf ident\n", COL(CLR_RED), COL(CLR_RST));
        fclose(fp);
        return -1;
    }

    if (memcmp(ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "%serror:%s not an ELF file\n", COL(CLR_RED), COL(CLR_RST));
        fclose(fp);
        return -1;
    }

    out->is32 = (ident[EI_CLASS] == ELFCLASS32);
    out->swap = (ident[EI_DATA] == ELFDATA2MSB);

    if (out->is32) {
        if (read_ehdr32(fp, out) < 0) {
            fprintf(stderr, "%serror:%s failed to read elf32 header\n", COL(CLR_RED), COL(CLR_RST));
            fclose(fp);
            return -1;
        }
    } else {
        if (read_ehdr64(fp, out) < 0) {
            fprintf(stderr, "%serror:%s failed to read elf64 header\n", COL(CLR_RED), COL(CLR_RST));
            fclose(fp);
            return -1;
        }
    }

    if (read_phdrs(fp, out) < 0) {
        fprintf(stderr, "%serror:%s truncated program headers\n", COL(CLR_RED), COL(CLR_RST));
        fclose(fp);
        return -1;
    }

    if (read_shdrs(fp, out) < 0) {
        fprintf(stderr, "%serror:%s truncated section headers\n", COL(CLR_RED), COL(CLR_RST));
        fclose(fp);
        return -1;
    }

    if (out->shnum == 0) {
        out->path = strdup(path);
        fclose(fp);
        return 0;
    }

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

    uint64_t entry = out->ehdr.e_entry;
    for (uint16_t i = 0; i < out->shnum; i++) {
        Elf64_Shdr *s = &out->sections[i];
        if (s->sh_addr && entry >= s->sh_addr && entry < s->sh_addr + s->sh_size) {
            out->entry_sec = i;
            break;
        }
    }

    for (uint16_t i = 0; i < out->shnum; i++) {
        if (out->sections[i].sh_type == SHT_DYNSYM) {
            uint32_t link = out->sections[i].sh_link;
            if (link < out->shnum) {
                load_symbols(fp, out, &out->sections[i], &out->sections[link],
                            &out->dynsyms, &out->dynsym_count, &out->dynstr,
                            SYM_SRC_DYNSYM);
            }
            break;
        }
    }

    for (uint16_t i = 0; i < out->shnum; i++) {
        if (out->sections[i].sh_type == SHT_SYMTAB) {
            uint32_t link = out->sections[i].sh_link;
            if (link < out->shnum) {
                load_symbols(fp, out, &out->sections[i], &out->sections[link],
                            &out->symtab, &out->symtab_count, &out->strtab,
                            SYM_SRC_SYMTAB);
            }
            break;
        }
    }

    out->path = strdup(path);
    fclose(fp);
    return 0;
}

void elf_print_header(const ElfFile *elf)
{
    const Elf64_Ehdr *e = &elf->ehdr;
    const char *class_str = elf->is32 ? "ELF32" : "ELF64";
    const char *endian_str = elf->swap ? "big-endian" : "little-endian";

    printf("\n%s[ELF HEADER]%s\n", COL(CLR_CYN), COL(CLR_RST));
    printf("  Class       : %s (%s)\n", class_str, endian_str);
    printf("  Type        : %s\n", elf_type_str(e->e_type));
    printf("  Machine     : %s\n", elf_machine_str(e->e_machine));

    if (elf->entry_sec >= 0 && elf->shstrtab) {
        const char *name = elf->shstrtab + elf->sections[elf->entry_sec].sh_name;
        if (elf->is32)
            printf("  Entry       : %s0x%08lx%s  (in %s)\n", COL(CLR_GRN), (unsigned long)e->e_entry, COL(CLR_RST), name);
        else
            printf("  Entry       : %s0x%016lx%s  (in %s)\n", COL(CLR_GRN), (unsigned long)e->e_entry, COL(CLR_RST), name);
    } else {
        if (elf->is32)
            printf("  Entry       : %s0x%08lx%s\n", COL(CLR_GRN), (unsigned long)e->e_entry, COL(CLR_RST));
        else
            printf("  Entry       : %s0x%016lx%s\n", COL(CLR_GRN), (unsigned long)e->e_entry, COL(CLR_RST));
    }

    printf("  PHDR offset : 0x%08lx (%u entries)\n", (unsigned long)e->e_phoff, e->e_phnum);
    printf("  SHDR offset : 0x%08lx (%u entries)\n", (unsigned long)e->e_shoff, e->e_shnum);
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

        const char *fcol = (p->p_flags & PF_X) ? CLR_GRN : ((p->p_flags & PF_W) ? CLR_YEL : "");

        if (elf->is32) {
            printf("  [%2u] %-12s  %s%s%s  OFF=0x%06lx  VADDR=%s0x%08lx%s  FILESZ=0x%06lx  MEMSZ=0x%06lx\n",
                   i, ph_type_str(p->p_type), COL(fcol), flags, COL(CLR_RST),
                   (unsigned long)p->p_offset,
                   COL(CLR_CYN), (unsigned long)p->p_vaddr, COL(CLR_RST),
                   (unsigned long)p->p_filesz,
                   (unsigned long)p->p_memsz);
        } else {
            printf("  [%2u] %-12s  %s%s%s  OFF=0x%06lx  VADDR=%s0x%016lx%s  FILESZ=0x%06lx  MEMSZ=0x%06lx\n",
                   i, ph_type_str(p->p_type), COL(fcol), flags, COL(CLR_RST),
                   (unsigned long)p->p_offset,
                   COL(CLR_CYN), (unsigned long)p->p_vaddr, COL(CLR_RST),
                   (unsigned long)p->p_filesz,
                   (unsigned long)p->p_memsz);
        }
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
            col = CLR_GRN;
        else if (s->sh_flags & SHF_WRITE)
            col = CLR_YEL;
        else if (s->sh_flags & SHF_ALLOC)
            col = CLR_CYN;

        printf("  %s[%2u] %-18s%s  TYPE=%-10s", COL(col), i, name, COL(CLR_RST), sh_type_str(s->sh_type));

        if (flags[0])
            printf("  FLAGS=%-3s", flags);
        if (s->sh_addr)
            printf("  ADDR=%s0x%08lx%s", COL(CLR_CYN), (unsigned long)s->sh_addr, COL(CLR_RST));
        if (s->sh_offset)
            printf("  OFF=0x%06lx", (unsigned long)s->sh_offset);
        if (s->sh_size)
            printf("  SIZE=0x%lx", (unsigned long)s->sh_size);

        if (i == elf->entry_sec)
            printf("  %s<-- entry%s", COL(CLR_BGRN), COL(CLR_RST));

        printf("\n");
    }
}

static void print_symbol_table(const ElfFile *elf, const ElfSymbolInfo *syms, size_t count, const char *title)
{
    printf("\n%s[%s]%s\n", COL(CLR_CYN), title, COL(CLR_RST));

    for (size_t i = 1; i < count; i++) {
        const ElfSymbolInfo *s = &syms[i];
        
        if (s->type != STT_FUNC && s->type != STT_OBJECT)
            continue;

        const char *tcol = (s->type == STT_FUNC) ? CLR_GRN : CLR_YEL;

        if (elf->is32) {
            printf("  %s%08lx%s  %s%-6s%s  %4lu  %s\n",
                   COL(CLR_CYN), (unsigned long)s->value, COL(CLR_RST),
                   COL(tcol), sym_type_str(s->type), COL(CLR_RST),
                   (unsigned long)s->size, s->name);
        } else {
            printf("  %s%016lx%s  %s%-6s%s  %4lu  %s\n",
                   COL(CLR_CYN), (unsigned long)s->value, COL(CLR_RST),
                   COL(tcol), sym_type_str(s->type), COL(CLR_RST),
                   (unsigned long)s->size, s->name);
        }
    }
}

void elf_print_dynsym(const ElfFile *elf)
{
    if (!elf->dynsyms || elf->dynsym_count == 0) {
        fprintf(stderr, "  %swarn:%s no .dynsym section\n", COL(CLR_YEL), COL(CLR_RST));
        return;
    }
    print_symbol_table(elf, elf->dynsyms, elf->dynsym_count, "DYNSYM");
}

void elf_print_symtab(const ElfFile *elf)
{
    if (!elf->symtab || elf->symtab_count == 0) {
        fprintf(stderr, "  %snote:%s no .symtab (binary is stripped)\n", COL(CLR_DIM), COL(CLR_RST));
        return;
    }
    print_symbol_table(elf, elf->symtab, elf->symtab_count, "SYMTAB");
}

void elf_print_entry(const ElfFile *elf)
{
    const Elf64_Ehdr *e = &elf->ehdr;

    printf("\n%s[ENTRY]%s\n", COL(CLR_CYN), COL(CLR_RST));
    
    if (elf->is32)
        printf("  Address : %s0x%08lx%s", COL(CLR_GRN), (unsigned long)e->e_entry, COL(CLR_RST));
    else
        printf("  Address : %s0x%016lx%s", COL(CLR_GRN), (unsigned long)e->e_entry, COL(CLR_RST));

    if (elf->entry_sec >= 0 && elf->shstrtab) {
        const char *name = elf->shstrtab + elf->sections[elf->entry_sec].sh_name;
        printf("  (in %s)", name);
    }
    printf("\n");
}

static const ElfSymbolInfo *find_symbol_for_addr(const ElfFile *elf, uint64_t addr)
{
    const ElfSymbolInfo *best = NULL;
    uint64_t best_dist = UINT64_MAX;

    for (size_t i = 1; i < elf->symtab_count; i++) {
        const ElfSymbolInfo *s = &elf->symtab[i];
        
        if (s->value == 0 || !s->name || !s->name[0])
            continue;
        if (s->type != STT_FUNC && s->type != STT_OBJECT)
            continue;
        if (s->value > addr)
            continue;

        if (s->size > 0 && addr < s->value + s->size)
            return s;

        uint64_t dist = addr - s->value;
        if (dist < best_dist) {
            best_dist = dist;
            best = s;
        }
    }

    for (size_t i = 1; i < elf->dynsym_count; i++) {
        const ElfSymbolInfo *s = &elf->dynsyms[i];
        
        if (s->value == 0 || !s->name || !s->name[0])
            continue;
        if (s->type != STT_FUNC && s->type != STT_OBJECT)
            continue;
        if (s->value > addr)
            continue;

        if (s->size > 0 && addr < s->value + s->size) {
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
    
    if (elf->is32)
        printf("  Address  : %s0x%08lx%s\n", COL(CLR_GRN), (unsigned long)addr, COL(CLR_RST));
    else
        printf("  Address  : %s0x%016lx%s\n", COL(CLR_GRN), (unsigned long)addr, COL(CLR_RST));

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
        
        if (elf->is32)
            printf("  Segment  : [%2d] %-12s  %s  VADDR=%s0x%08lx%s\n",
                   seg_idx, ph_type_str(p->p_type), flags,
                   COL(CLR_CYN), (unsigned long)p->p_vaddr, COL(CLR_RST));
        else
            printf("  Segment  : [%2d] %-12s  %s  VADDR=%s0x%016lx%s\n",
                   seg_idx, ph_type_str(p->p_type), flags,
                   COL(CLR_CYN), (unsigned long)p->p_vaddr, COL(CLR_RST));

        uint64_t file_off = p->p_offset + (addr - p->p_vaddr);
        printf("  File off : 0x%08lx\n", (unsigned long)file_off);
    } else {
        printf("  Segment  : %s(not in any PT_LOAD segment)%s\n", COL(CLR_DIM), COL(CLR_RST));
    }

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
        printf("  Section  : [%2d] %s%s%s\n", sec_idx, COL(CLR_GRN), name, COL(CLR_RST));
    } else {
        printf("  Section  : %s(no matching section)%s\n", COL(CLR_DIM), COL(CLR_RST));
    }

    const ElfSymbolInfo *sym = find_symbol_for_addr(elf, addr);
    if (sym) {
        uint64_t offset = addr - sym->value;
        const char *src = (sym->source == SYM_SRC_SYMTAB) ? "SYMTAB" : "DYNSYM";
        
        if (offset == 0)
            printf("  Symbol   : %s%s%s (%s, %s)\n", COL(CLR_MAG), sym->name, COL(CLR_RST), sym_type_str(sym->type), src);
        else
            printf("  Symbol   : %s%s%s+0x%lx (%s, %s)\n", COL(CLR_MAG), sym->name, COL(CLR_RST), (unsigned long)offset, sym_type_str(sym->type), src);
    } else {
        printf("  Symbol   : %s(no matching symbol)%s\n", COL(CLR_DIM), COL(CLR_RST));
    }
}

int elf_find_section(const ElfFile *elf, const char *name, uint64_t *off, uint64_t *size)
{
    if (!elf->shstrtab || elf->shnum == 0)
        return -1;

    for (uint16_t i = 0; i < elf->shnum; i++) {
        const Elf64_Shdr *s = &elf->sections[i];
        const char *sname = elf->shstrtab + s->sh_name;

        if (strcmp(sname, name) == 0) {
            *off = s->sh_offset;
            *size = s->sh_size;
            return 0;
        }
    }
    return -1;
}

void elf_hexdump(const ElfFile *elf, uint64_t offset, size_t len)
{
    if (!elf->path)
        return;

    FILE *fp = fopen(elf->path, "rb");
    if (!fp) {
        fprintf(stderr, "%serror:%s can't reopen file\n", COL(CLR_RED), COL(CLR_RST));
        return;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);

    if (offset >= (uint64_t)fsize) {
        fprintf(stderr, "%serror:%s offset out of bounds\n", COL(CLR_RED), COL(CLR_RST));
        fclose(fp);
        return;
    }

    if (offset + len > (uint64_t)fsize)
        len = fsize - offset;

    uint8_t *buf = malloc(len);
    if (!buf) {
        fclose(fp);
        return;
    }

    fseek(fp, offset, SEEK_SET);
    size_t rd = fread(buf, 1, len, fp);
    fclose(fp);

    printf("\n");
    for (size_t i = 0; i < rd; i += 16) {
        printf("  %s%08lx%s  ", COL(HEX_ADDR), (unsigned long)(offset + i), COL(CLR_RST));

        for (int j = 0; j < 16; j++) {
            if (i + j < rd) {
                uint8_t b = buf[i + j];
                const char *col;
                
                if (b == 0x00)
                    col = HEX_NULL;
                else if (b < 0x20)
                    col = HEX_LOW;
                else if (b < 0x7f)
                    col = HEX_PRINT;
                else
                    col = HEX_HIGH;
                
                printf("%s%02x%s ", COL(col), b, COL(CLR_RST));
            } else {
                printf("   ");
            }
            if (j == 7) printf(" ");
        }

        printf(" %s|%s", COL(CLR_DIM), COL(CLR_RST));
        for (int j = 0; j < 16 && i + j < rd; j++) {
            uint8_t c = buf[i + j];
            if (c >= 0x20 && c < 0x7f)
                printf("%s%c%s", COL(HEX_ASCII), c, COL(CLR_RST));
            else
                printf("%s.%s", COL(CLR_DIM), COL(CLR_RST));
        }
        printf("%s|%s\n", COL(CLR_DIM), COL(CLR_RST));
    }

    free(buf);
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
    free(elf->path);
}

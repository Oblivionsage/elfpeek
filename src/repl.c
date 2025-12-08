// src/repl.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "elf_parser.h"
#include "colors.h"

#ifdef HAVE_READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

/* Prompt is now dynamic, see get_prompt() */
#define MAX_ARGS 16

static ElfFile g_elf;
static int g_file_open = 0;

typedef int (*cmd_fn)(int argc, char **argv);

struct command {
    const char *name;
    const char *alias;
    const char *help;
    cmd_fn fn;
    int needs_file;
};

/* forward decls */
static int cmd_open(int argc, char **argv);
static int cmd_close(int argc, char **argv);
static int cmd_info(int argc, char **argv);
static int cmd_sections(int argc, char **argv);
static int cmd_phdr(int argc, char **argv);
static int cmd_entry(int argc, char **argv);
static int cmd_symbols(int argc, char **argv);
static int cmd_resolve(int argc, char **argv);
static int cmd_dump(int argc, char **argv);
static int cmd_help(int argc, char **argv);
static int cmd_quit(int argc, char **argv);

static struct command cmds[] = {
    {"open",     "o",   "open <path>           open ELF file",            cmd_open,     0},
    {"close",    NULL,  "close                 close current file",       cmd_close,    1},
    {"info",     "i",   "info                  show ELF header",          cmd_info,     1},
    {"sections", "s",   "sections              list section headers",     cmd_sections, 1},
    {"phdr",     "p",   "phdr                  list program headers",     cmd_phdr,     1},
    {"entry",    "e",   "entry                 show entry point",         cmd_entry,    1},
    {"symbols",  "sym", "symbols [dyn|sym]     dump symbol tables",       cmd_symbols,  1},
    {"resolve",  "r",   "resolve <addr>        resolve virtual address",  cmd_resolve,  1},
    {"dump",     "d",   "dump <.sec|@off> [n]  hex dump",                  cmd_dump,     1},
    {"help",     "?",   "help [cmd]            show help",                cmd_help,     0},
    {"quit",     "q",   "quit                  exit",                     cmd_quit,     0},
    {NULL, NULL, NULL, NULL, 0}
};

static const char *get_prompt(void)
{
    static char prompt[256];
    if (g_file_open && g_elf.path) {
        const char *name = strrchr(g_elf.path, '/');
        name = name ? name + 1 : g_elf.path;
        snprintf(prompt, sizeof(prompt), "%s(%s:%s)%s ", 
                 COL(CLR_BGRN), "elfpeek", name, COL(CLR_RST));
    } else {
        snprintf(prompt, sizeof(prompt), "%s(elfpeek)%s ", 
                 COL(CLR_CYN), COL(CLR_RST));
    }
    return prompt;
}

static char *read_line(void)
{
    const char *prompt = get_prompt();
#ifdef HAVE_READLINE
    char *line = readline(prompt);
    if (line && *line)
        add_history(line);
    return line;
#else
    static char buf[1024];
    printf("%s", prompt);
    fflush(stdout);
    if (!fgets(buf, sizeof(buf), stdin))
        return NULL;
    buf[strcspn(buf, "\n")] = 0;
    return buf;
#endif
}

static int tokenize(char *line, char **argv, int max)
{
    int argc = 0;
    char *p = line;

    while (*p && argc < max - 1) {
        while (*p && isspace(*p)) p++;
        if (!*p) break;
        argv[argc++] = p;
        while (*p && !isspace(*p)) p++;
        if (*p) *p++ = 0;
    }
    argv[argc] = NULL;
    return argc;
}

static struct command *find_cmd(const char *name)
{
    for (struct command *c = cmds; c->name; c++) {
        if (strcmp(c->name, name) == 0)
            return c;
        if (c->alias && strcmp(c->alias, name) == 0)
            return c;
    }
    return NULL;
}

/* ---------- handlers ---------- */

static int cmd_open(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: open <path>\n");
        return 0;
    }

    if (g_file_open) {
        fprintf(stderr, "file already open, close first\n");
        return 0;
    }

    if (elf_parse_file(argv[1], &g_elf) != 0)
        return 0;

    g_file_open = 1;
    printf("opened %s (%s, %s-endian)\n",
           argv[1],
           g_elf.is32 ? "ELF32" : "ELF64",
           g_elf.swap ? "big" : "little");
    return 0;
}

static int cmd_close(int argc, char **argv)
{
    (void)argc; (void)argv;
    elf_free(&g_elf);
    memset(&g_elf, 0, sizeof(g_elf));
    g_file_open = 0;
    printf("closed\n");
    return 0;
}

static int cmd_info(int argc, char **argv)
{
    (void)argc; (void)argv;
    elf_print_header(&g_elf);
    return 0;
}

static int cmd_sections(int argc, char **argv)
{
    (void)argc; (void)argv;
    elf_print_sections(&g_elf);
    return 0;
}

static int cmd_phdr(int argc, char **argv)
{
    (void)argc; (void)argv;
    elf_print_phdrs(&g_elf);
    return 0;
}

static int cmd_entry(int argc, char **argv)
{
    (void)argc; (void)argv;
    elf_print_entry(&g_elf);
    return 0;
}

static int cmd_symbols(int argc, char **argv)
{
    const char *which = (argc > 1) ? argv[1] : "all";

    if (strcmp(which, "dyn") == 0 || strcmp(which, "dynsym") == 0) {
        elf_print_dynsym(&g_elf);
    } else if (strcmp(which, "sym") == 0 || strcmp(which, "symtab") == 0) {
        elf_print_symtab(&g_elf);
    } else {
        elf_print_dynsym(&g_elf);
        elf_print_symtab(&g_elf);
    }
    return 0;
}

static int cmd_resolve(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: resolve <addr>\n");
        return 0;
    }

    uint64_t addr = strtoull(argv[1], NULL, 0);
    elf_resolve_addr(&g_elf, addr);
    return 0;
}

static int cmd_dump(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: dump <.section|@offset> [len]\n");
        fprintf(stderr, "  dump .text        dump first 256 bytes of .text\n");
        fprintf(stderr, "  dump .rodata 64   dump 64 bytes of .rodata\n");
        fprintf(stderr, "  dump @0x1000 128  dump 128 bytes at file offset 0x1000\n");
        return 0;
    }

    uint64_t off, size;
    size_t len = 256;

    if (argc > 2)
        len = strtoull(argv[2], NULL, 0);

    if (argv[1][0] == '@') {
        off = strtoull(argv[1] + 1, NULL, 0);
        size = len; // we'll bounds-check in hexdump
    } else if (argv[1][0] == '.') {
        if (elf_find_section(&g_elf, argv[1], &off, &size) < 0) {
            fprintf(stderr, "section '%s' not found\n", argv[1]);
            return 0;
        }
        if (len > size) len = size;
    } else {
        fprintf(stderr, "use .section or @offset\n");
        return 0;
    }

    elf_hexdump(&g_elf, off, len);
    return 0;
}

static int cmd_help(int argc, char **argv)
{
    if (argc > 1) {
        struct command *c = find_cmd(argv[1]);
        if (c)
            printf("  %s\n", c->help);
        else
            printf("unknown command '%s'\n", argv[1]);
        return 0;
    }

    printf("\nCommands:\n");
    for (struct command *c = cmds; c->name; c++)
        printf("  %s\n", c->help);
    printf("\n");
    return 0;
}

static int cmd_quit(int argc, char **argv)
{
    (void)argc; (void)argv;
    if (g_file_open) {
        elf_free(&g_elf);
        g_file_open = 0;
    }
    return -1;
}

/* ---------- main loop ---------- */

void repl_run(void)
{
    char *line;
    char *argv[MAX_ARGS];
    int argc;

    printf("elfpeek interactive mode\ntype 'help' for commands, 'quit' to exit\n\n");

    while ((line = read_line()) != NULL) {
        argc = tokenize(line, argv, MAX_ARGS);
        if (argc == 0) {
#ifdef HAVE_READLINE
            free(line);
#endif
            continue;
        }

        struct command *cmd = find_cmd(argv[0]);
        if (!cmd) {
            fprintf(stderr, "unknown command '%s'\n", argv[0]);
        } else if (cmd->needs_file && !g_file_open) {
            fprintf(stderr, "no file open\n");
        } else {
            int ret = cmd->fn(argc, argv);
            if (ret < 0) {
#ifdef HAVE_READLINE
                free(line);
#endif
                break;
            }
        }

#ifdef HAVE_READLINE
        free(line);
#endif
    }
}

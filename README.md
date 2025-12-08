<h1 align="center">elfpeek</h1>

<p align="center">
  <img src="assets/logo.png" alt="elfpeek logo" width="200">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/written%20in-C-blue?style=flat-square" alt="C">
  <img src="https://img.shields.io/badge/platform-Linux-green?style=flat-square" alt="Linux">
  <img src="https://img.shields.io/badge/arch-ELF32%20%7C%20ELF64-orange?style=flat-square" alt="ELF32 | ELF64">
  <img src="https://img.shields.io/github/license/Oblivionsage/elfpeek?style=flat-square" alt="License">
  <img src="https://img.shields.io/github/stars/Oblivionsage/elfpeek?style=flat-square" alt="Stars">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/no%20dependencies-✓-brightgreen?style=flat-square" alt="No Dependencies">
  <img src="https://img.shields.io/badge/minimal-~1K%20LOC-purple?style=flat-square" alt="Minimal">
  <img src="https://img.shields.io/badge/reverse%20engineering-tool-red?style=flat-square" alt="RE Tool">
</p>

<p align="center">
  Minimal ELF inspector with interactive REPL for quick binary analysis
</p>

---

## Features

- **Interactive REPL** with readline support (history, tab completion)
- **Dynamic colored prompt** - shows current file: `(elfpeek:ls)`
- **Colored hexdump** - null (gray), printable (green), control (red), high bytes (yellow)
- **Colored sections** - executable (green), writable (yellow), read-only (cyan)
- **ELF32/ELF64** support with little/big endian
- **Address resolver** - maps VA to segment, section, file offset, nearest symbol
- **Symbol tables** - both `.dynsym` and `.symtab`
- **No dependencies** - only glibc and `<elf.h>`

## Build
```bash
make
```

Optional: Install `libreadline-dev` for command history in REPL.

## Usage

### Interactive Mode
```bash
./elfpeek
```
```
elfpeek interactive mode
type 'help' for commands, 'quit' to exit

(elfpeek) open /bin/ls
opened /bin/ls (ELF64, little-endian)
(elfpeek:ls) info
(elfpeek:ls) sections
(elfpeek:ls) dump .rodata 64
(elfpeek:ls) resolve 0x6760
(elfpeek:ls) quit
```

### One-shot Mode
```bash
./elfpeek /bin/ls           # show headers, sections, symbols
./elfpeek /bin/ls 0x6760    # resolve address
```

## Commands

| Command | Alias | Description |
|---------|-------|-------------|
| `open <path>` | `o` | Open ELF file |
| `close` | | Close current file |
| `info` | `i` | Show ELF header |
| `sections` | `s` | List section headers |
| `phdr` | `p` | List program headers |
| `entry` | `e` | Show entry point |
| `symbols [dyn\|sym]` | `sym` | Dump symbol tables |
| `resolve <addr>` | `r` | Resolve virtual address |
| `dump <.sec\|@off> [n]` | `d` | Hex dump (section or offset) |
| `help` | `?` | Show help |
| `quit` | `q` | Exit |

## Examples

### ELF Header
```
(elfpeek:ls) info

[ELF HEADER]
  Class       : ELF64 (little-endian)
  Type        : DYN (Shared object)
  Machine     : x86_64
  Entry       : 0x0000000000006760  (in .text)
  PHDR offset : 0x00000040 (14 entries)
  SHDR offset : 0x00026428 (30 entries)
```

### Colored Sections
```
(elfpeek:ls) sections

[SECTIONS]
  [11] .init     TYPE=PROGBITS  FLAGS=AX   ADDR=0x00004000  <-- green (executable)
  [14] .text     TYPE=PROGBITS  FLAGS=AX   ADDR=0x00004740  <-- entry
  [16] .rodata   TYPE=PROGBITS  FLAGS=A    ADDR=0x0001b000  <-- cyan (read-only)
  [25] .data     TYPE=PROGBITS  FLAGS=WA   ADDR=0x00027000  <-- yellow (writable)
  [26] .bss      TYPE=NOBITS    FLAGS=WA   ADDR=0x00027280
```

### Colored Hexdump
```
(elfpeek:ls) dump .rodata 64

  0001b000  01 00 02 00 cd cc cc 3d  66 66 66 3f cd cc 8c 3f  |.......=fff?...?|
  0001b010  00 00 80 5f 00 00 00 5f  00 00 20 41 00 00 00 00  |..._..._.. A....|
```

Color coding:
- **Gray/dim**: null bytes (`00`)
- **Green**: printable ASCII (`20`-`7E`)
- **Red**: control characters (`01`-`1F`)
- **Yellow**: high bytes (`80`-`FF`)
- **Cyan**: addresses

### Address Resolution
```
(elfpeek:ls) resolve 0x6760

[ADDR]
  Address  : 0x0000000000006760
  Segment  : [ 3] LOAD  R X  VADDR=0x0000000000004000
  File off : 0x00006760
  Section  : [14] .text
  Symbol   : error_at_line+0x1c89 (FUNC, DYNSYM)
```

### Dump by File Offset
```
(elfpeek:ls) dump @0x1000 32

  00001000  7c 05 00 00 11 00 1a 00  a8 72 02 00 00 00 00 00  ||........r......|
```

## Why?

Not a replacement for `readelf` or `objdump`. Just a quick, focused tool for common RE questions:

- What's the binary layout?
- Which segment/section contains this address?
- What's the file offset for this VA?
- What bytes are at this location?
- Which function owns this address?

Also serves as readable ELF parsing example in C. Handles stripped and segment-only binaries gracefully.

## Test Binaries

`tests/` contains sample ELF files:

| File | Description |
|------|-------------|
| `elf32_le.bin` | 32-bit little-endian (i386) |
| `elf32_be.bin` | 32-bit big-endian (PowerPC) |
| `elf64_be.bin` | 64-bit big-endian (PowerPC64) |
| `elf64_le_pie.bin` | PIE executable |
| `elf64_le_static.bin` | Statically linked |
| `elf64_le_dynsym_only.bin` | Stripped, dynsym only |
| `elf64_le_so.bin` | Shared object |
| `elf64_le_segments_only.bin` | No section headers |

## License

MIT

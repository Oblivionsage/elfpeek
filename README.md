# elfpeek

Minimal ELF64 inspector written in C for quick binary layout inspection

![demo](assets/demo.gif)

## Build

```bash
make
```

This builds a single `elfpeek` binary `(gcc -std=c11 -Wall -Wextra -O2)`

No external dependencies; only glibc and `<elf.h>`. Currently supports ELF64 little-endian binaries (Linux x86_64 style)

## Usage

```bash
./elfpeek <elf-file> [addr]
```

- `elf-file` – path to an ELF64 binary
- `addr` (optional) – virtual address to resolve
  - `0x...` → hex
  - otherwise → decimal

## Why?

This is not trying to replace `readelf` or `objdump`.

The goal is to have a small, focused tool that answers a few common questions quickly:

- *"What does the layout of this ELF actually look like?"*
- *"Which segment/section does this virtual address belong to?"*
- *"Where is this address in the file (offset) so I can poke it with a hex editor?"*
- *"Where is the entry point, and which section owns it?"*
- *"Which function does this address belong to?"*

The code is intentionally small and straightforward C, so it also works as a "readable ELF64 example" if you're learning how ELF headers, sections and symbols are wired together. Also works on stripped or segment-only ELF binaries where some tools can be picky.

## Features

- ELF32 and ELF64 support
- Little-endian and big-endian architectures (x86, ARM, PowerPC, MIPS, SPARC)
- ELF header parsing (type, machine, entry point)
- Program headers (segments + permissions)
- Section headers (with simple flag-based coloring)
- Symbol tables (`.dynsym` and `.symtab`) dump
- Address resolver:
  - Given a VA, show:
    - which segment it's in
    - which section it's in
    - corresponding file offset
    - nearest symbol (`symbol+offset` format)
- Graceful handling of section-less ELF binaries

## Example

```bash
$ ./elfpeek /bin/ls

[ELF HEADER]
  Type        : DYN (Shared object)
  Machine     : x86_64
  Entry       : 0x0000000000006760  (in .text)
  PHDR offset : 0x00000040 (14 entries)
  SHDR offset : 0x00026428 (30 entries)
  SHSTR index : 29

[PROGRAM HEADERS]
  [ 0] PHDR          R    OFF=0x000040  VADDR=0x0000000000000040  FILESZ=0x000310  MEMSZ=0x000310
  [ 3] LOAD          R X  OFF=0x004000  VADDR=0x0000000000004000  FILESZ=0x016cf9  MEMSZ=0x016cf9
  ...

[SECTIONS]
  [14] .text               TYPE=PROGBITS    FLAGS=AX   ADDR=0x00004740  OFF=0x004740  SIZE=0x165ae  <-- entry
  [16] .rodata             TYPE=PROGBITS    FLAGS=A    ADDR=0x0001b000  OFF=0x01b000  SIZE=0x5388
  ...

[DYNSYM]
  0000000000000000  FUNC       0  printf
  0000000000000000  FUNC       0  malloc
  ...

[SYMTAB]
  0000000000001200  FUNC     311  main
  00000000000017c0  FUNC    1312  elf_parse_file
  ...
```

Address resolution with symbol lookup:

```bash
$ ./elfpeek ./elfpeek 0x1250

[ADDR]
  Address  : 0x0000000000001250
  Segment  : [ 3] LOAD          R X  VADDR=0x0000000000001000
  File off : 0x00001250
  Section  : [16] .text
  Symbol   : main+0x50 (FUNC, SYMTAB)
```

## Colors

Section names are lightly colored by flags:

- **Green** – executable (X)
- **Yellow** – writable (W)
- **Cyan** – read-only allocated (A)

The idea is to keep output readable in a normal terminal without turning it into a rainbow.

## TODO

- [ ] Hex dump of sections

# elfpeek

Minimal ELF64 inspector written in C for quick binary layout inspection

## Build

```bash
make
```

This builds a single `elfpeek` binary (`gcc -std=c11 -Wall -Wextra -O2`).

No external dependencies; only glibc and `<elf.h>`. Currently supports ELF64 little-endian binaries (Linux x86_64 style)

## Usage

```bash
./elfpeek <elf-file> [addr]
```

- `elf-file` – path to an ELF64 binary
- `addr` (optional) – virtual address to resolve
  - `0x...` → hex
  - otherwise → decimal

## Features

- ELF header parsing (type, machine, entry point)
- Program headers (segments + permissions)
- Section headers (with simple flag-based coloring)
- Dynamic symbol table (`.dynsym`) dump (FUNC / OBJECT)
- Address resolver:
  - Given a VA, show:
    - which segment it's in
    - which section it's in
    - corresponding file offset

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
```

Address resolution:

```bash
$ ./elfpeek /bin/ls 0x4740

[ADDR]
  Address  : 0x0000000000004740
  Segment  : [ 3] LOAD          R X  VADDR=0x0000000000004000
  File off : 0x00004740
  Section  : [14] .text
```

## Colors

Section names are lightly colored by flags:

- **Green** – executable (X)
- **Yellow** – writable (W)
- **Cyan** – read-only allocated (A)

The idea is to keep output readable in a normal terminal without turning it into a rainbow.

## TODO

- [ ] 32-bit ELF support
- [ ] `.symtab` parsing
- [ ] Big-endian support

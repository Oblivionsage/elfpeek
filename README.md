# elfpeek

Minimal ELF64 parser for inspecting headers, sections, and symbols.

## Build

```
make
```

## Usage

```
./elfpeek <elf-file> [addr]
```

## Features

- ELF header parsing (type, machine, entry point)
- Program headers (segments with permissions)
- Section headers (with flag-based coloring)
- Dynamic symbol table (.dynsym)
- Address resolver (find segment/section for any address)

## Example

```
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

```
$ ./elfpeek /bin/ls 0x4740

[ADDR]
  Address  : 0x0000000000004740
  Segment  : [ 3] LOAD          R X  VADDR=0x0000000000004000
  File off : 0x00004740
  Section  : [14] .text
```

## Colors

Sections are colored by flags:
- Green: executable (X)
- Yellow: writable (W)  
- Cyan: read-only allocated (A)


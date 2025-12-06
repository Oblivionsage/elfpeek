# elfpeek

Minimal ELF64 parser for inspecting headers and sections.

## Build

```
make
```

## Usage
```
./elfpeek <elf-file>
```

## Example
```
$ ./elfpeek /bin/ls

[ELF HEADER]
  Type        : DYN (Shared object)
  Machine     : x86_64
  Entry       : 0x0000000000006760
  PHDR offset : 0x00000040 (14 entries)
  SHDR offset : 0x00026428 (30 entries)
  SHSTR index : 29

[SECTIONS]
  [ 0]                     TYPE=NULL      
  [ 1] .note.gnu.property  TYPE=NOTE        FLAGS=A    ADDR=0x00000350  OFF=0x000350  SIZE=0x20
  [ 2] .note.gnu.build-id  TYPE=NOTE        FLAGS=A    ADDR=0x00000370  OFF=0x000370  SIZE=0x24
  [ 3] .interp             TYPE=PROGBITS    FLAGS=A    ADDR=0x00000394  OFF=0x000394  SIZE=0x1c
  [ 4] .gnu.hash           TYPE=GNU_HASH    FLAGS=A    ADDR=0x000003b0  OFF=0x0003b0  SIZE=0xb0
  [ 5] .dynsym             TYPE=DYNSYM      FLAGS=A    ADDR=0x00000460  OFF=0x000460  SIZE=0xcf0
  [ 6] .dynstr             TYPE=STRTAB      FLAGS=A    ADDR=0x00001150  OFF=0x001150  SIZE=0x652
  [ 7] .gnu.version        TYPE=VERSYM      FLAGS=A    ADDR=0x000017a2  OFF=0x0017a2  SIZE=0x114
  [ 8] .gnu.version_r      TYPE=VERNEED     FLAGS=A    ADDR=0x000018b8  OFF=0x0018b8  SIZE=0xe0
  [ 9] .rela.dyn           TYPE=RELA        FLAGS=A    ADDR=0x00001998  OFF=0x001998  SIZE=0x1428
  [10] .rela.plt           TYPE=RELA        FLAGS=A    ADDR=0x00002dc0  OFF=0x002dc0  SIZE=0xa50
  [11] .init               TYPE=PROGBITS    FLAGS=AX   ADDR=0x00004000  OFF=0x004000  SIZE=0x17
  [12] .plt                TYPE=PROGBITS    FLAGS=AX   ADDR=0x00004020  OFF=0x004020  SIZE=0x6f0
  [13] .plt.got            TYPE=PROGBITS    FLAGS=AX   ADDR=0x00004710  OFF=0x004710  SIZE=0x20
  [14] .text               TYPE=PROGBITS    FLAGS=AX   ADDR=0x00004740  OFF=0x004740  SIZE=0x165ae
  [15] .fini               TYPE=PROGBITS    FLAGS=AX   ADDR=0x0001acf0  OFF=0x01acf0  SIZE=0x9
  [16] .rodata             TYPE=PROGBITS    FLAGS=A    ADDR=0x0001b000  OFF=0x01b000  SIZE=0x5388
  [17] .eh_frame_hdr       TYPE=PROGBITS    FLAGS=A    ADDR=0x00020388  OFF=0x020388  SIZE=0xa74
  [18] .eh_frame           TYPE=PROGBITS    FLAGS=A    ADDR=0x00020e00  OFF=0x020e00  SIZE=0x3718
  [19] .note.ABI-tag       TYPE=NOTE        FLAGS=A    ADDR=0x00024518  OFF=0x024518  SIZE=0x20
  [20] .init_array         TYPE=INIT_ARRAY  FLAGS=WA   ADDR=0x00025fb0  OFF=0x024fb0  SIZE=0x8
  [21] .fini_array         TYPE=FINI_ARRAY  FLAGS=WA   ADDR=0x00025fb8  OFF=0x024fb8  SIZE=0x8
  [22] .data.rel.ro        TYPE=PROGBITS    FLAGS=WA   ADDR=0x00025fc0  OFF=0x024fc0  SIZE=0xa38
  [23] .dynamic            TYPE=DYNAMIC     FLAGS=WA   ADDR=0x000269f8  OFF=0x0259f8  SIZE=0x210
  [24] .got                TYPE=PROGBITS    FLAGS=WA   ADDR=0x00026c08  OFF=0x025c08  SIZE=0x3e8
  [25] .data               TYPE=PROGBITS    FLAGS=WA   ADDR=0x00027000  OFF=0x026000  SIZE=0x280
  [26] .bss                TYPE=NOBITS      FLAGS=WA   ADDR=0x00027280  OFF=0x026280  SIZE=0x1318
  [27] .gnu_debugaltlink   TYPE=PROGBITS    OFF=0x026280  SIZE=0x49
  [28] .gnu_debuglink      TYPE=PROGBITS    OFF=0x0262cc  SIZE=0x34
  [29] .shstrtab           TYPE=STRTAB      OFF=0x026300  SIZE=0x126
```

Sections are colored by flags:
- Green: executable (X)
- Yellow: writable (W)
- Cyan: read-only allocated (A)



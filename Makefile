CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -O2 -I./include

READLINE := $(shell pkg-config --exists readline 2>/dev/null && echo yes)
ifeq ($(READLINE),yes)
    CFLAGS += -DHAVE_READLINE $(shell pkg-config --cflags readline)
    LDFLAGS += $(shell pkg-config --libs readline)
endif

SRCS = src/main.c src/elf_parser.c src/repl.c
OBJS = $(SRCS:.c=.o)
TARGET = elfpeek

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

src/main.o: src/main.c
	$(CC) $(CFLAGS) -c -o src/main.o src/main.c

src/elf_parser.o: src/elf_parser.c
	$(CC) $(CFLAGS) -c -o src/elf_parser.o src/elf_parser.c

src/repl.o: src/repl.c
	$(CC) $(CFLAGS) -c -o src/repl.o src/repl.c

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean

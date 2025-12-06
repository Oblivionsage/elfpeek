CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2
INCLUDES = -Iinclude

SRC = src/main.c src/elf_parser.c
TARGET = elfpeek

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(SRC)

clean:
	rm -f $(TARGET)

.PHONY: all clean

CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2
INCLUDES = -Iinclude

SRC = src/main.c
TARGET = elfpeek

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(SRC)

clean:
	rm -f $(TARGET)

.PHONY: all clean

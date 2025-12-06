#include <stdio.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <elf-file>\n", argv[0]);
        return 1;
    }

    printf("file: %s\n", argv[1]);
    return 0;
}

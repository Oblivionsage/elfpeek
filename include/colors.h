#ifndef COLORS_H
#define COLORS_H

#define CLR_RED   "\x1b[31m"
#define CLR_GRN   "\x1b[32m"
#define CLR_YEL   "\x1b[33m"
#define CLR_BLU   "\x1b[34m"
#define CLR_MAG   "\x1b[35m"
#define CLR_CYN   "\x1b[36m"
#define CLR_RST   "\x1b[0m"

extern int use_colors;

#define COL(c) (use_colors ? (c) : "")

#endif

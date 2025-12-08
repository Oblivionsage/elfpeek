// include/colors.h
#ifndef COLORS_H
#define COLORS_H

#include <unistd.h>

#define CLR_RST  "\033[0m"
#define CLR_BOLD "\033[1m"
#define CLR_DIM  "\033[2m"

#define CLR_RED  "\033[31m"
#define CLR_GRN  "\033[32m"
#define CLR_YEL  "\033[33m"
#define CLR_BLU  "\033[34m"
#define CLR_MAG  "\033[35m"
#define CLR_CYN  "\033[36m"
#define CLR_WHT  "\033[37m"

#define CLR_BRED "\033[1;31m"
#define CLR_BGRN "\033[1;32m"
#define CLR_BYEL "\033[1;33m"
#define CLR_BCYN "\033[1;36m"

extern int use_colors;
#define COL(c) (use_colors ? (c) : "")

#define HEX_ADDR   CLR_CYN
#define HEX_NULL   CLR_DIM
#define HEX_LOW    CLR_RED
#define HEX_PRINT  CLR_GRN
#define HEX_HIGH   CLR_YEL
#define HEX_ASCII  CLR_BGRN

#endif

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <zlib.h>

// level:
//      -1 - 9
//      Z_DEFAULT_COMPRESSION = -1 = 6
//      0 = no compression
//      9 = slowest compression

int def(FILE *source, FILE *dest, int level); 
int inf(FILE *source, FILE *dest);
#include <bzlib.h>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <stdexcept>

// These constants are not part of the BZip2 Library
const unsigned int bz2_BUFFER_SIZE = 4096 * sizeof(char);
const unsigned int bz2_VERBOSITY = 0; // 0 - 4; 0 = silent
const unsigned int bz2_SMALL = 0; // 0 or 1
const unsigned int bz2_WORKFACTOR = 0; // 0 - 250; 0 = 30
const unsigned int bz2_BLOCKSIZE100K = 9; // 1 - 9; 9 = best compression

// in should be opened with "rb"
// out should be opened with "wb"
int bz2_compress(FILE * in, FILE * out);
int bz2_decompress(FILE * in, FILE * out);

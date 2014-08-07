#include <cmath>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <zlib.h>

#if defined(MSDOS) || defined(OS2) || defined(WIN32) || defined(__CYGWIN__)
#  include <fcntl.h>
#  include <io.h>
#  define SET_BINARY_MODE(file) setmode(fileno(file), O_BINARY)
#else
#  define SET_BINARY_MODE(file)
#endif

#define CHUNK 16384
#define ZLIB_WINDOWBITS 15      // ZLIB format
#define DEFLATE_WINDOWBITS -15  // Raw DEFLATE

// level:
//      -1 - 9
//      Z_DEFAULT_COMPRESSION = -1 = 6
//      0 = no compression
//      9 = slowest compression

int zlib_compress(const std::string & src, std::string & dst, int windowBits, int level = Z_DEFAULT_COMPRESSION);
int zlib_decompress(const std::string & src, std::string & dst, int windowBits);
void zerr(int ret);

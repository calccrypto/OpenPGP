#include <assert.h>
#include <bzlib.h>
#include <iostream>
#include <sstream>
#include <stdexcept>

const unsigned int bz2_BUFFER_SIZE = 4096 * sizeof(char);   // size of buffer
const unsigned int bz2_BLOCKSIZE100K = 9;                   // 1 - 9; 9 = best compression
const unsigned int bz2_VERBOSITY = 0;                       // 0 - 4; 0 = silent
const unsigned int bz2_WORKFACTOR = 0;                      // 0 - 250; 0 = 30
const unsigned int bz2_SMALL = 0;                           // 0 or 1

int bz2_compress(const std::string & src, std::string & dst);
int bz2_decompress(const std::string & src, std::string & dst);

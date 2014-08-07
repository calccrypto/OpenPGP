#ifndef __OpenPGP_COMPRESS__
#define __OpenPGP_COMPRESS__

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

#include "pgpbzip2.h"
#include "pgpzlib.h"

std::string PGP_compress(const uint8_t alg, const std::string & data);
std::string PGP_decompress(const uint8_t alg, const std::string & data);

#endif 
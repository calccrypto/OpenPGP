#ifndef HASHES_H
#define HASHES_H

#include "../common/cryptomath.h"
#include "../common/includes.h"
#include "Hash.h"

#include "MD5.h"
#include "RIPEMD160.h"
#include "SHA1.h"
#include "SHA256.h"
#include "SHA224.h"
#include "SHA512.h"
#include "SHA384.h"

std::string use_hash(uint8_t flag, const std::string & data);

#endif

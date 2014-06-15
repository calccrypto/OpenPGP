#ifndef __TESTS_AESECBGFSBOX256__
#define __TESTS_AESECBGFSBOX256__

#include <string>
#include <vector>

// Test vectors from <http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip>

static const std::string AES256_ECB_GFSBOX_KEY = "0000000000000000000000000000000000000000000000000000000000000000";

static const std::vector<std::string> AES256_ECB_GFSBOX_PLAIN = {
    "014730f80ac625fe84f026c60bfd547d",
    "0b24af36193ce4665f2825d7b4749c98",
    "761c1fe41a18acf20d241650611d90f1",
    "8a560769d605868ad80d819bdba03771",
    "91fbef2d15a97816060bee1feaa49afe",
};

static const std::vector<std::string> AES256_ECB_GFSBOX_CIPHER = {
    "5c9d844ed46f9885085e5d6a4f94c7d7",
    "a9ff75bd7cf6613d3731c77c3b6d0c04",
    "623a52fcea5d443e48d9181ab32c7421",
    "38f2c7ae10612415d27ca190d27da8b4",
    "1bc704f1bce135ceb810341b216d7abe",
};

#endif // __TESTS_AESECBGFSBOX256__

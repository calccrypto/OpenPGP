#ifndef __TESTS_ECBGFSBOX128__
#define __TESTS_ECBGFSBOX128__

#include <string>
#include <vector>

// Test vectors from <http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip>

static const std::string AES128_ECB_GFSBOX_KEY = "00000000000000000000000000000000";

static const std::vector<std::string> AES128_ECB_GFSBOX_PLAIN = {
    "f34481ec3cc627bacd5dc3fb08f273e6",
    "9798c4640bad75c7c3227db910174e72",
    "96ab5c2ff612d9dfaae8c31f30c42168",
    "6a118a874519e64e9963798a503f1d35",
    "cb9fceec81286ca3e989bd979b0cb284",
    "b26aeb1874e47ca8358ff22378f09144",
    "58c8e00b2631686d54eab84b91f0aca1",
};

static const std::vector<std::string> AES128_ECB_GFSBOX_CIPHER = {
    "0336763e966d92595a567cc9ce537f5e",
    "a9a1631bf4996954ebc093957b234589",
    "ff4f8391a6a40ca5b25d23bedd44a597",
    "dc43be40be0e53712f7e2bf5ca707209",
    "92beedab1895a94faa69b632e5cc47ce",
    "459264f4798f6a78bacb89c15ed3d601",
    "08a4e2efec8a8e3312ca7460b9040bbf",
};

#endif // __TESTS_ECBGFSBOX128__

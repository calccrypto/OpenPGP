#ifndef __TESTS_AESECBGFSBOX192__
#define __TESTS_AESECBGFSBOX192__

#include <string>
#include <vector>

// Test vectors from <http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip>

static const std::string AES192_ECB_GFSBOX_KEY = "000000000000000000000000000000000000000000000000";

static const std::vector<std::string> AES192_ECB_GFSBOX_PLAIN = {
    "1b077a6af4b7f98229de786d7516b639",
    "9c2d8842e5f48f57648205d39a239af1",
    "bff52510095f518ecca60af4205444bb",
    "51719783d3185a535bd75adc65071ce1",
    "26aa49dcfe7629a8901a69a9914e6dfd",
    "941a4773058224e1ef66d10e0a6ee782",
};

static const std::vector<std::string> AES192_ECB_GFSBOX_CIPHER = {
    "275cfc0413d8ccb70513c3859b1d0f72",
    "c9b8135ff1b5adc413dfd053b21bd96d",
    "4a3650c3371ce2eb35e389a171427440",
    "4f354592ff7c8847d2d0870ca9481b7c",
    "d5e08bf9a182e857cf40b3a36ee248cc",
    "067cd9d3749207791841562507fa9626",
};

#endif // __TESTS_AESECBGFSBOX192__

#ifndef __TESTS_IDEATESTVECTORSSET4__
#define __TESTS_IDEATESTVECTORSSET4__

#include <string>
#include <vector>

// Test vectors from <https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/idea/Idea-128-64.verified.test-vectors>

static const std::vector<std::string> IDEA_SET4_KEY = {
    "000102030405060708090a0b0c0d0e0f",
    "2bd6459f82c5b300952c49104881ff48",
};

static const std::vector<std::string> IDEA_SET4_PLAIN = {
    "0011223344556677",
    "ea024714ad5c4d84",
};

static const std::vector<std::string> IDEA_SET4_CIPHER = {
    "f526ab9a62c0d258",
    "c8fb51d3516627a8",
};

#endif // __TESTS_IDEATESTVECTORSSET4__

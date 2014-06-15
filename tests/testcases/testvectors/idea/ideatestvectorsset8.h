#ifndef __TEST_IDEATESTVECTORSSET8__
#define __TEST_IDEATESTVECTORSSET8__

#include <string>
#include <vector>

// Test vectors from <https://www.cosic.esat.kuleuven.be/nessie/testvectors/bc/idea/Idea-128-64.verified.test-vectors>

static const std::vector<std::string> IDEA_SET8_KEY = {
    "000102030405060708090a0b0c0d0e0f",
    "2bd6459f82c5b300952c49104881ff48",
};

static const std::vector<std::string> IDEA_SET8_PLAIN = {
    "db2d4a92aa68273f",
    "f129a6601ef62a47",
};

static const std::vector<std::string> IDEA_SET8_CIPHER = {
    "0011223344556677",
    "ea024714ad5c4d84",
};

#endif // __TEST_IDEATESTVECTORSSET8__

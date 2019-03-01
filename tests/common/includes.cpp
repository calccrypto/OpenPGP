#include <gtest/gtest.h>

#include <iomanip>
#include <sstream>
#include <stdexcept>

#include "common/includes.h"

TEST(toint, 2) {
    for(uint64_t i = 0; i < 256; i++) {
        EXPECT_EQ(toint(makebin(i), 2), i);
    }
}

TEST(toint, 8) {
    for(uint64_t i = 0; i < 256; i++) {
        std::stringstream s;
        s << std::oct << i;
        EXPECT_EQ(toint(s.str(), 8), i);
    }
}

TEST(toint, 10) {
    for(uint64_t i = 0; i < 256; i++) {
        std::stringstream s;
        s << std::dec << i;
        EXPECT_EQ(toint(s.str(), 10), i);
    }
}

TEST(toint, 16) {
    for(uint64_t i = 0; i < 256; i++) {
        std::stringstream s;
        s << std::hex << i;
        EXPECT_EQ(toint(s.str(), 16), i);
    }
}

TEST(toint, 256) {
    EXPECT_EQ(toint(std::string("\x00\x01\x02\x03\x04\x05\x06\x07", 8),  256), 0x0001020304050607ULL);
    EXPECT_EQ(toint(std::string("\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 8),  256), 0x08090a0b0c0d0e0fULL);
    EXPECT_EQ(toint(std::string("\x07\x06\x05\x04\x03\x02\x01\x00", 8),  256), 0x0706050403020100ULL);
    EXPECT_EQ(toint(std::string("\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08", 8),  256), 0x0f0e0d0c0b0a0908ULL);

    EXPECT_EQ(toint(std::string("\x00\x01\x02\x03\x04\x05\x06\x07"
                                "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16), 256), 0x08090a0b0c0d0e0fULL);
    EXPECT_EQ(toint(std::string("\x0f\x0e\x0d\x0c\x0b\x0a\x09\x08"
                                "\x07\x06\x05\x04\x03\x02\x01\x00", 16), 256), 0x0706050403020100ULL);
}

TEST(toint, empty) {
    EXPECT_EQ(toint("", 2),   0ULL);
    EXPECT_EQ(toint("", 8),   0ULL);
    EXPECT_EQ(toint("", 10),  0ULL);
    EXPECT_EQ(toint("", 16),  0ULL);
    EXPECT_EQ(toint("", 256), 0ULL);
}

TEST(toint, bad) {
    EXPECT_EQ(toint("~", 2),   0ULL);
    EXPECT_EQ(toint("~", 8),   0ULL);
    EXPECT_EQ(toint("~", 10),  0ULL);
    EXPECT_EQ(toint("~", 16),  0ULL);
}

TEST(toint, bad_base) {
    EXPECT_THROW(toint("", 0), std::runtime_error);
}

TEST(little_end, 2) {
    std::string src = "";
    std::string expected = "";
    for(std::size_t i = 0; i < 256; i++) {
        src += makebin((char) i, 8);
        expected += makebin((char) (255 - i), 8);
    }

    EXPECT_EQ(little_end(src, 2), expected);
}

TEST(little_end, 16) {
    std::string src = "";
    std::string expected = "";
    for(std::size_t i = 0; i < 256; i++) {
        src += makehex((char) i, 2);
        expected += makehex((char) (255 - i), 2);
    }

    EXPECT_EQ(little_end(src, 16), expected);
}

TEST(little_end, 256) {
    std::string src(256, 0);
    std::string expected(256, 0);
    for(std::size_t i = 0; i < 256; i++) {
        src[i] = i;
        expected[i] = 255 - i;
    }

    EXPECT_EQ(little_end(src, 256), expected);
}

TEST(little_end, bad_base) {
    EXPECT_THROW(little_end("", 0), std::runtime_error);
}

TEST(makebin, good) {
    for(uint16_t i = 0; i < 256; i++) {
        const std::string bin = std::string(1, ((((char) i) >> 7) & 1) | '0') +
                                std::string(1, ((((char) i) >> 6) & 1) | '0') +
                                std::string(1, ((((char) i) >> 5) & 1) | '0') +
                                std::string(1, ((((char) i) >> 4) & 1) | '0') +
                                std::string(1, ((((char) i) >> 3) & 1) | '0') +
                                std::string(1, ((((char) i) >> 2) & 1) | '0') +
                                std::string(1, ((((char) i) >> 1) & 1) | '0') +
                                std::string(1, ((((char) i) >> 0) & 1) | '0');
        EXPECT_EQ(makebin((uint8_t) i, 8),               bin);
        EXPECT_EQ(makebin((uint8_t) i, 16), "00000000" + bin);
    }
}

TEST(makehex, good) {
    for(uint16_t i = 0; i < 256; i++) {
        std::stringstream s;
        s << std::setw(2) << std::setfill('0') << std::hex << i;
        const std::string hex = s.str();
        EXPECT_EQ(makehex((uint8_t) i, 2),        hex);
        EXPECT_EQ(makehex((uint8_t) i, 4), "00" + hex);
    }
}

TEST(byte, good) {
    for(uint16_t i = 0; i < 256; i++) {
        EXPECT_EQ(byte((- (i << 8)) | i, 0), (uint8_t)  i);
        EXPECT_EQ(byte((- (i << 8)) | i, 1), (uint8_t) -i);
    }
}

TEST(bintohex, lower) {
    EXPECT_EQ(bintohex(makebin(0x0123456789abcdefULL, 64), false), "0123456789abcdef");
}

TEST(bintohex, upper) {
    EXPECT_EQ(bintohex(makebin(0x0123456789abcdefULL, 64), true),  "0123456789ABCDEF");
}

TEST(bintohex, zero) {
    EXPECT_EQ(bintohex("", false), "");
}

TEST(bintohex, bad_bits) {
    EXPECT_THROW(bintohex("0",  false), std::runtime_error);
    EXPECT_THROW(bintohex("00", false), std::runtime_error);
    EXPECT_THROW(bintohex("00", false), std::runtime_error);
}

TEST(binify, string) {
    for(uint16_t i = 0; i < 256; i++) {
        const std::string bin = makebin(i, 8);

        // no leading 0s
        EXPECT_EQ(binify(std::string(1, (char) i), 0), bin);

        // 8 leading 0s
        EXPECT_EQ(binify(std::string(1, (char) i), 16), std::string(8, '0') + bin);
    }
}

TEST(binify, char) {
    for(uint16_t i = 0; i < 256; i++) {
        EXPECT_EQ(binify((char) i), makebin(i, 8));
    }
}

TEST(hexlify, string) {
    for(uint16_t i = 0; i < 256; i++) {
        const std::string hex = makehex(i, 2);

        // no leading 0s
        EXPECT_EQ(hexlify(std::string(1, (char) i), false), hex);
    }
}

TEST(hexlify, char) {
    for(uint16_t i = 0; i < 256; i++) {
        EXPECT_EQ(hexlify((char) i), makehex(i, 2));
    }
}

TEST(unhexlify, good) {
    for(uint16_t i = 0; i < 256; i++) {
        const std::string orig(1, (char) i);
        EXPECT_EQ(unhexlify(hexlify(orig)), orig);
    }
}

TEST(unhexlify, bad_size) {
    EXPECT_THROW(unhexlify("0"), std::runtime_error);
}

TEST(unhexlify, bad_char) {
    EXPECT_THROW(unhexlify("0~"), std::runtime_error);
    EXPECT_THROW(unhexlify("~0"), std::runtime_error);
}

TEST(pkcs5, good) {
    const std::string orig = "data";
    for(unsigned int i = 1; i < 256; i++) {
        EXPECT_EQ(remove_pkcs5(pkcs5(orig, i)), orig);
    }
}

TEST(zfill, good) {
    for(unsigned int i = 0; i < 256; i++) {
        EXPECT_EQ(zfill("", i, '0'), std::string(i, '0'));
    }
}

TEST(zfill, length_reached) {
    const std::string str(256, 0);
    for(unsigned int i = 0; i < 256; i++) {
        EXPECT_EQ(zfill(str, i, '0'), str);
    }
}

TEST(ROL, good) {
    const std::string str = "ABCDEFGH";
    const uint64_t val = toint(str, 256);

    for(uint8_t i = 0; i < 64; i++) {
        EXPECT_EQ(ROL(str, i), unhexlify(makehex((val << i) | (val >> (64 - i)), 16)));
    }
}

TEST(strings, and) {
    const uint64_t val1 = 0x05050505a5a5a5a5ULL;
    const uint64_t val2 = 0xa0a0a0a05a5a5a5aULL;

    const std::string str1 = unhexlify(makehex(val1, 16));
    const std::string str2 = unhexlify(makehex(val2, 16));

    EXPECT_EQ(and_strings(str1, str2), std::string("\x00\x00\x00\x00\x00\x00\x00\x00", 8));
}

TEST(strings, or) {
    const uint64_t val1 = 0x05050505a5a5a5a5ULL;
    const uint64_t val2 = 0xa0a0a0a05a5a5a5aULL;

    const std::string str1 = unhexlify(makehex(val1, 16));
    const std::string str2 = unhexlify(makehex(val2, 16));

    EXPECT_EQ(or_strings(str1, str2), std::string("\xa5\xa5\xa5\xa5\xff\xff\xff\xff", 8));
}

TEST(strings, xor) {
    const uint64_t val1 = 0x05050505a5a5a5a5ULL;
    const uint64_t val2 = 0xa0a0a0a05a5a5a5aULL;

    const std::string str1 = unhexlify(makehex(val1, 16));
    const std::string str2 = unhexlify(makehex(val2, 16));

    EXPECT_EQ(xor_strings(str1, str2), std::string("\xa5\xa5\xa5\xa5\xff\xff\xff\xff", 8));
}

TEST(trim_whitespace, empty) {
    const std::string str = "";
    EXPECT_EQ(trim_whitespace(str, true, true), str);
}

TEST(trim_whitespace, no_whitespace) {
    const std::string str = "string";
    EXPECT_EQ(trim_whitespace(str, true, true), str);
}

TEST(trim_whitespace, only_whitespace) {
    const std::string str = whitespace;
    EXPECT_EQ(trim_whitespace(str, true, true), "");
}

TEST(trim_whitespace, remove_leading) {
    const std::string str = whitespace + "str" + whitespace + "ing" + whitespace;
    EXPECT_EQ(trim_whitespace(str, true, false), str.substr(whitespace.size(), str.size() - whitespace.size()));
}

TEST(trim_whitespace, remove_trailing) {
    const std::string str = whitespace + "str" + whitespace + "ing" + whitespace;
    EXPECT_EQ(trim_whitespace(str, false, true), str.substr(0, str.size() - whitespace.size()));
}

TEST(trim_whitespace, remove_both) {
    const std::string str = whitespace + "str" + whitespace + "ing" + whitespace;
    EXPECT_EQ(trim_whitespace(str, true, true), str.substr(whitespace.size(), str.size() - whitespace.size() - whitespace.size()));
}

TEST(trim_whitespace, remove_none) {
    const std::string str = whitespace + "str" + whitespace + "ing" + whitespace;
    EXPECT_EQ(trim_whitespace(str, false, false), str);
}

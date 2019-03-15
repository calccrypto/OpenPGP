#include <gtest/gtest.h>

#include <map>
#include <memory>
#include <sstream>

#include "Misc/mpi.h"
#include "common/includes.h"

const int COUNT = 10;

TEST(MPI, add_sub){
    OpenPGP::MPI a = OpenPGP::random(512);
    for (int i = 0; i < COUNT; ++i){
        OpenPGP::MPI b = OpenPGP::random(512);
        OpenPGP::MPI c = a + b;
        c -= a;
        c -= b;
        EXPECT_EQ(c, 0);
    }
}

TEST(MPI, mul_div_mod){
    for (int i = 0; i < COUNT; ++i){
        OpenPGP::MPI a = OpenPGP::random(400), b = a;
        a <<= (i+1);
        a += i;
        OpenPGP::MPI c = a % b, d = a / b;
        OpenPGP::MPI e = d * b + c;
        EXPECT_EQ(e-a, 0);
    }
}

TEST(MPI, lshift){
    OpenPGP::MPI a = OpenPGP::random(200), b, c = 1;
    for (int i = 0; i < COUNT; ++i){
        b = a << (i+1);
        c += c;
        OpenPGP::MPI d = a * c;
        EXPECT_EQ(d-b, 0);
    }
}

TEST(MPI, rshift){
    OpenPGP::MPI a = OpenPGP::random(200), b, c = 1;
    for (int i = 0; i < COUNT; ++i){
        b = a >> (i+1);
        c += c;
        OpenPGP::MPI d = a / c;
        EXPECT_EQ(d-b, 0);
    }
}

static const std::map <std::string, OpenPGP::MPI> tests = {
    std::make_pair(std::string(    "\x01\x02\x03", 3),   0x010203UL),
    std::make_pair(std::string("\x04\x05\x06\x07", 4), 0x04050607UL),
    std::make_pair(std::string("\x08\x09\x0a\x0b", 4), 0x08090a0bUL),
    std::make_pair(std::string("\x0c\x0d\x0e\x0f", 4), 0x0c0d0e0fUL),
};

TEST(MPI, convert_raw){
    for(std::pair <const std::string, OpenPGP::MPI> const & test : tests) {
        EXPECT_EQ(OpenPGP::rawtompi(test.first), test.second);
        EXPECT_EQ(OpenPGP::mpitoraw(test.second), test.first);
    }
}

TEST(MPI, convert_hex){
    for(std::pair <const std::string, OpenPGP::MPI> const & test : tests) {
        const std::string hex = hexlify(test.first);
        EXPECT_EQ(OpenPGP::hextompi(hex), test.second);
        EXPECT_EQ(OpenPGP::mpitohex(test.second), hex);
    }
}

TEST(MPI, convert_dec){
    for(std::pair <const std::string, OpenPGP::MPI> const & test : tests) {
        std::stringstream s;
        s << toint(hexlify(test.first), 16);
        EXPECT_EQ(OpenPGP::dectompi(s.str()), test.second);
        EXPECT_EQ(OpenPGP::mpitodec(test.second), s.str());
    }
}

TEST(MPI, convert_bin){
    for(std::pair <const std::string, OpenPGP::MPI> const & test : tests) {
        std::string bin = binify(test.first, 0);

        // remove leading 0s
        std::string::size_type msb = bin.find_first_not_of('0');
        bin = bin.substr(msb, bin.size() - msb);

        EXPECT_EQ(OpenPGP::bintompi(bin), test.second);
        EXPECT_EQ(OpenPGP::mpitobin(test.second), bin);
    }
}

TEST(MPI, bitsize) {
    OpenPGP::MPI mpi = 1;
    for(std::size_t i = 1; i < 128; i++) {
        EXPECT_EQ(OpenPGP::bitsize(mpi), i);
        mpi <<= 1;
    }
}

TEST(MPI, read_write) {
    for(std::size_t i = 0; i < 128; i++) {
        OpenPGP::MPI value = OpenPGP::random(32);
        const std::string str = OpenPGP::write_MPI(value);
        std::string::size_type pos = 0;
        EXPECT_EQ(OpenPGP::read_MPI(str, pos), value);
    }
}

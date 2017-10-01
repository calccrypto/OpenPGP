#include <gtest/gtest.h>

#include "Misc/mpi.h"

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

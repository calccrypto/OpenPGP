#include <gtest/gtest.h>

#include "mpi.h"

const int COUNT = 10;

TEST(MPITest, test_add_sub){
    PGPMPI a = random(512);
    for (int i = 0; i < COUNT; ++i){
        PGPMPI b = random(512);
        PGPMPI c = a + b;
        c -= a;
        c -= b;
        EXPECT_EQ(c, 0);
    }
}

TEST(MPITest, test_mul_div_mod){
    for (int i = 0; i < COUNT; ++i){
        PGPMPI a = random(400), b = a;
        a <<= i+1;
        a += i;
        PGPMPI c = a % b, d = a / b;
        PGPMPI e = d * b + c;
        EXPECT_EQ(e-a, 0);
    }
}

TEST(MPITest, test_lshift){
    PGPMPI a = random(200), b, c = 1;
    for (int i = 0; i < COUNT; ++i){
        b = a << i+1;
        c += c;
        PGPMPI d = a * c;
        EXPECT_EQ(d-b, 0);
    }
}

TEST(MPITest, test_rshift){
    PGPMPI a = random(200), b, c = 1;
    for (int i = 0; i < COUNT; ++i){
        b = a >> i+1;
        c += c;
        PGPMPI d = a / c;
        EXPECT_EQ(d-b, 0);
    }
}

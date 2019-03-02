#include <gtest/gtest.h>

#include "Packets/Tag0.h"

TEST(Tag0, NoCreate) {
    EXPECT_THROW(OpenPGP::Packet::Tag0(), std::runtime_error);
}

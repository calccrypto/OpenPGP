#include <gtest/gtest.h>

#include "Packets/Tag2/Sub1.h"

TEST(Tag2Sub1, NoCreate) {
    EXPECT_THROW(OpenPGP::Subpacket::Tag2::Sub1(), std::runtime_error);
}

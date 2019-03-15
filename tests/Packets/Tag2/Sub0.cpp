#include <gtest/gtest.h>

#include "Packets/Tag2/Sub0.h"

TEST(Tag2Sub0, NoCreate) {
    EXPECT_THROW(OpenPGP::Subpacket::Tag2::Sub0(), std::runtime_error);
}

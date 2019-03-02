#include <gtest/gtest.h>

#include "Packets/Tag2/Sub18.h"

TEST(Tag2Sub18, NoCreate) {
    EXPECT_THROW(OpenPGP::Subpacket::Tag2::Sub18(), std::runtime_error);
}

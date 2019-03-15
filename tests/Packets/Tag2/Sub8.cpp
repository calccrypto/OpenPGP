#include <gtest/gtest.h>

#include "Packets/Tag2/Sub8.h"

TEST(Tag2Sub8, NoCreate) {
    EXPECT_THROW(OpenPGP::Subpacket::Tag2::Sub8(), std::runtime_error);
}

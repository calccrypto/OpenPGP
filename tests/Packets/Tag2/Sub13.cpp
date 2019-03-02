#include <gtest/gtest.h>

#include "Packets/Tag2/Sub13.h"

TEST(Tag2Sub13, NoCreate) {
    EXPECT_THROW(OpenPGP::Subpacket::Tag2::Sub13(), std::runtime_error);
}

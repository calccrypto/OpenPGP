#include <gtest/gtest.h>

#include "Packets/Tag2/Sub17.h"

TEST(Tag2Sub17, NoCreate) {
    EXPECT_THROW(OpenPGP::Subpacket::Tag2::Sub17(), std::runtime_error);
}

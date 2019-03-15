#include <gtest/gtest.h>

#include "Packets/Tag2/Sub19.h"

TEST(Tag2Sub19, NoCreate) {
    EXPECT_THROW(OpenPGP::Subpacket::Tag2::Sub19(), std::runtime_error);
}

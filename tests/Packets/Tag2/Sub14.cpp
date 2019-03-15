#include <gtest/gtest.h>

#include "Packets/Tag2/Sub14.h"

TEST(Tag2Sub14, NoCreate) {
    EXPECT_THROW(OpenPGP::Subpacket::Tag2::Sub14(), std::runtime_error);
}

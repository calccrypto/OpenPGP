#include <gtest/gtest.h>

#include "Packets/Tag2/Sub15.h"

TEST(Tag2Sub15, NoCreate) {
    EXPECT_THROW(OpenPGP::Subpacket::Tag2::Sub15(), std::runtime_error);
}

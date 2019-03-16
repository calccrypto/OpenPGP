#include <gtest/gtest.h>

#include "Packets/Packets.h"
#include "Packets/Partial.h"

TEST(Partial, Constructor) {
    using namespace OpenPGP::Packet;

    Partial empty;
    EXPECT_EQ(empty.get_partial(), PartialBodyLength::NOT_PARTIAL);

    Partial empty_copy(empty);
    EXPECT_EQ(empty.get_partial(), empty_copy.get_partial());

    Partial not_partial(PartialBodyLength::NOT_PARTIAL);
    EXPECT_EQ(not_partial.get_partial(), PartialBodyLength::NOT_PARTIAL);

    Partial not_partial_copy(not_partial);
    EXPECT_EQ(not_partial.get_partial(), not_partial_copy.get_partial());

    Partial partial(PartialBodyLength::PARTIAL);
    EXPECT_EQ(partial.get_partial(), PartialBodyLength::PARTIAL);

    Partial partial_copy(partial);
    EXPECT_EQ(partial.get_partial(), partial_copy.get_partial());
}

TEST(Partial, set_get) {
    using namespace OpenPGP::Packet;

    Partial part;
    EXPECT_NO_THROW(part.set_partial(PartialBodyLength::NOT_PARTIAL));
    EXPECT_EQ(part.get_partial(), PartialBodyLength::NOT_PARTIAL);

    EXPECT_NO_THROW(part.set_partial(PartialBodyLength::PARTIAL));
    EXPECT_EQ(part.get_partial(), PartialBodyLength::PARTIAL);
}

TEST(Partial, can_have_partial_length_tag) {
    using namespace OpenPGP::Packet;

    EXPECT_FALSE(Partial::can_have_partial_length(RESERVED));
    EXPECT_FALSE(Partial::can_have_partial_length(PUBLIC_KEY_ENCRYPTED_SESSION_KEY));
    EXPECT_FALSE(Partial::can_have_partial_length(SIGNATURE));
    EXPECT_FALSE(Partial::can_have_partial_length(SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY));
    EXPECT_FALSE(Partial::can_have_partial_length(ONE_PASS_SIGNATURE));
    EXPECT_FALSE(Partial::can_have_partial_length(SECRET_KEY));
    EXPECT_FALSE(Partial::can_have_partial_length(PUBLIC_KEY));
    EXPECT_FALSE(Partial::can_have_partial_length(SECRET_SUBKEY));
    EXPECT_TRUE (Partial::can_have_partial_length(COMPRESSED_DATA));
    EXPECT_TRUE (Partial::can_have_partial_length(SYMMETRICALLY_ENCRYPTED_DATA));
    EXPECT_FALSE(Partial::can_have_partial_length(MARKER_PACKET));
    EXPECT_TRUE (Partial::can_have_partial_length(LITERAL_DATA));
    EXPECT_FALSE(Partial::can_have_partial_length(TRUST));
    EXPECT_FALSE(Partial::can_have_partial_length(USER_ID));
    EXPECT_FALSE(Partial::can_have_partial_length(PUBLIC_SUBKEY));
    EXPECT_FALSE(Partial::can_have_partial_length(USER_ATTRIBUTE));
    EXPECT_TRUE (Partial::can_have_partial_length(SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA));
    EXPECT_FALSE(Partial::can_have_partial_length(MODIFICATION_DETECTION_CODE));
    EXPECT_FALSE(Partial::can_have_partial_length(60));
    EXPECT_FALSE(Partial::can_have_partial_length(61));
    EXPECT_FALSE(Partial::can_have_partial_length(62));
    EXPECT_FALSE(Partial::can_have_partial_length(63));
}

TEST(Partial, can_have_partial_length_ptr) {
    using namespace OpenPGP::Packet;

    EXPECT_FALSE(Partial::can_have_partial_length(std::make_shared <Tag1>  ()));
    EXPECT_FALSE(Partial::can_have_partial_length(std::make_shared <Tag2>  ()));
    EXPECT_FALSE(Partial::can_have_partial_length(std::make_shared <Tag3>  ()));
    EXPECT_FALSE(Partial::can_have_partial_length(std::make_shared <Tag4>  ()));
    EXPECT_FALSE(Partial::can_have_partial_length(std::make_shared <Tag5>  ()));
    EXPECT_FALSE(Partial::can_have_partial_length(std::make_shared <Tag6>  ()));
    EXPECT_FALSE(Partial::can_have_partial_length(std::make_shared <Tag7>  ()));
    EXPECT_TRUE (Partial::can_have_partial_length(std::make_shared <Tag8>  ()));
    EXPECT_TRUE (Partial::can_have_partial_length(std::make_shared <Tag9>  ()));
    EXPECT_FALSE(Partial::can_have_partial_length(std::make_shared <Tag10> ()));
    EXPECT_TRUE (Partial::can_have_partial_length(std::make_shared <Tag11> ()));
    EXPECT_FALSE(Partial::can_have_partial_length(std::make_shared <Tag12> ()));
    EXPECT_FALSE(Partial::can_have_partial_length(std::make_shared <Tag13> ()));
    EXPECT_FALSE(Partial::can_have_partial_length(std::make_shared <Tag14> ()));
    EXPECT_FALSE(Partial::can_have_partial_length(std::make_shared <Tag17> ()));
    EXPECT_TRUE (Partial::can_have_partial_length(std::make_shared <Tag18> ()));
    EXPECT_FALSE(Partial::can_have_partial_length(std::make_shared <Tag19> ()));
    EXPECT_FALSE(Partial::can_have_partial_length(std::make_shared <Tag60> ()));
    EXPECT_FALSE(Partial::can_have_partial_length(std::make_shared <Tag61> ()));
    EXPECT_FALSE(Partial::can_have_partial_length(std::make_shared <Tag62> ()));
    EXPECT_FALSE(Partial::can_have_partial_length(std::make_shared <Tag63> ()));
}

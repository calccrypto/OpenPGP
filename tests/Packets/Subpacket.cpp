#include <gtest/gtest.h>

#include "Packets/Subpacket.h"

class TestSubpacket final : public OpenPGP::Subpacket::Sub {
    // these just have to be defined, not available
    private:
        void actual_read(const std::string &) {}

        std::string show_type() const{
            return "";
        }

        void show_contents(HumanReadable &) const{}
};

TEST(Subpacket, Constructor) {
    TestSubpacket testsubpacket;
    EXPECT_EQ(testsubpacket.get_critical(), false);
    EXPECT_EQ(testsubpacket.get_type(), 0);
    EXPECT_EQ(testsubpacket.get_size(), 0);
}

TEST(Subpacket, set_get) {
    const bool critical = false;
    const uint8_t type = 0;
    const std::size_t size = 0;

    TestSubpacket testsubpacket;
    EXPECT_NO_THROW(testsubpacket.set_critical(critical));
    EXPECT_EQ(testsubpacket.get_critical(), critical);
    EXPECT_NO_THROW(testsubpacket.set_type(type));
    EXPECT_EQ(testsubpacket.get_type(), type);
    EXPECT_NO_THROW(testsubpacket.set_size(size));
    EXPECT_EQ(testsubpacket.get_size(), size);
}

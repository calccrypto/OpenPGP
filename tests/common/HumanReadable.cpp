#include <gtest/gtest.h>

#include <common/HumanReadable.h>

TEST(HumanReadable, generated_prefix) {
    HumanReadable hr(1, 2);
    hr << "";
    EXPECT_EQ(hr.get(), "  \n");

    hr << HumanReadable::DOWN;
    hr << "";
    EXPECT_EQ(hr.get(), "  \n   \n");

    hr << HumanReadable::UP;
    hr << "";
    EXPECT_EQ(hr.get(), "  \n   \n  \n");
}

TEST(HumanReadable, user_prefix) {
    HumanReadable hr("\t", " ");
    hr << "";
    EXPECT_EQ(hr.get(), "\t\n");

    hr << HumanReadable::DOWN;
    hr << "";
    EXPECT_EQ(hr.get(), "\t\n\t \n");

    hr << HumanReadable::UP;
    hr << "";
    EXPECT_EQ(hr.get(), "\t\n\t \n\t\n");
}

TEST(HumanReadable, up_down) {
    HumanReadable hr(0, 0);

    const std::size_t depth = 10;

    for(std::size_t i = 0; i < depth; i++) {
        EXPECT_EQ(hr.down(), i + 1);
        EXPECT_EQ(hr.curr_level(), i + 1);
    }

    for(std::size_t i = 0; i < depth; i++) {
        EXPECT_EQ(hr.up(), depth - i - 1);
        EXPECT_EQ(hr.curr_level(), depth - i - 1);
    }

    // try to go past root
    EXPECT_EQ(hr.up(), 0);
}

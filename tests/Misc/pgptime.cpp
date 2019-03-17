#include <gtest/gtest.h>

#include "Misc/pgptime.h"

TEST(time, show_time) {
    EXPECT_EQ(OpenPGP::show_time(0), OpenPGP::dayofweek[4] + " " + OpenPGP::month[0] + " 1 00:00:00 UTC 1970");
}

TEST(time, show_date) {
    EXPECT_EQ(OpenPGP::show_date(0), "1970-01-01");
}

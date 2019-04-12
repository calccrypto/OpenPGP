#include <gtest/gtest.h>

#include "Misc/pgptime.h"

TEST(time, show_time) {
    EXPECT_EQ(OpenPGP::show_time(0), OpenPGP::dayofweek[4] + " " + OpenPGP::month[0] + " 1 00:00:00 UTC 1970");
}

TEST(time, show_date) {
    EXPECT_EQ(OpenPGP::show_date(0), "1970-01-01");
}

TEST(time, show_dt) {
    EXPECT_EQ(OpenPGP::show_dt(-1 * 60 * 60 * 24 * 365), "1 year ago");
    EXPECT_EQ(OpenPGP::show_dt(-1 * 60 * 60 * 24),       "1 day ago");
    EXPECT_EQ(OpenPGP::show_dt(-1 * 60 * 60),            "1 hour ago");
    EXPECT_EQ(OpenPGP::show_dt(-1 * 60),                 "1 minute ago");
    EXPECT_EQ(OpenPGP::show_dt(-1),                      "1 second ago");
    EXPECT_EQ(OpenPGP::show_dt(0),                       "now");
    EXPECT_EQ(OpenPGP::show_dt(1),                       "1 second from now");
    EXPECT_EQ(OpenPGP::show_dt(60),                      "1 minute from now");
    EXPECT_EQ(OpenPGP::show_dt(60 * 60),                 "1 hour from now");
    EXPECT_EQ(OpenPGP::show_dt(60 * 60 * 24),            "1 day from now");
    EXPECT_EQ(OpenPGP::show_dt(60 * 60 * 24 * 365),      "1 year from now");
}

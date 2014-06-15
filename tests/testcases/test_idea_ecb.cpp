#include <gtest/gtest.h>

#include "Encryptions/IDEA.h"

#include "testvectors/idea/ideatestvectorsset1.h"
#include "testvectors/idea/ideatestvectorsset2.h"
#include "testvectors/idea/ideatestvectorsset3.h"
#include "testvectors/idea/ideatestvectorsset4.h"
#include "testvectors/idea/ideatestvectorsset5.h"
#include "testvectors/idea/ideatestvectorsset6.h"
#include "testvectors/idea/ideatestvectorsset7.h"
#include "testvectors/idea/ideatestvectorsset8.h"

TEST(IDEATest, test_idea_ecb_set1) {

    ASSERT_EQ(IDEA_SET1_KEY.size(), IDEA_SET1_CIPHER.size());

    const std::string UNHEX_IDEA_SET1_PLAIN = unhexlify(IDEA_SET1_PLAIN);

    for ( unsigned int i = 0; i < IDEA_SET1_KEY.size(); ++i ) {
        auto idea = IDEA(unhexlify(IDEA_SET1_KEY[i]));
        EXPECT_EQ(hexlify(idea.encrypt(UNHEX_IDEA_SET1_PLAIN)), IDEA_SET1_CIPHER[i]);
        EXPECT_EQ(idea.decrypt(unhexlify(IDEA_SET1_CIPHER[i])), UNHEX_IDEA_SET1_PLAIN);
    }
}

TEST(IDEATest, test_idea_ecb_set2) {

    ASSERT_EQ(IDEA_SET2_PLAIN.size(), IDEA_SET2_CIPHER.size());

    const std::string UNHEX_IDEA_SET2_KEY = unhexlify(IDEA_SET2_KEY);

    for ( unsigned int i = 0; i < IDEA_SET2_PLAIN.size(); ++i ) {
        auto idea = IDEA(UNHEX_IDEA_SET2_KEY);
        EXPECT_EQ(hexlify(idea.encrypt(unhexlify(IDEA_SET2_PLAIN[i]))), IDEA_SET2_CIPHER[i]);
        EXPECT_EQ(hexlify(idea.decrypt(unhexlify(IDEA_SET2_CIPHER[i]))), IDEA_SET2_PLAIN[i]);
    }
}

TEST(IDEATest, test_idea_ecb_set3) {

    ASSERT_EQ(IDEA_SET3_KEY.size(), IDEA_SET3_PLAIN.size());
    ASSERT_EQ(IDEA_SET3_PLAIN.size(), IDEA_SET3_CIPHER.size());

    for ( unsigned int i = 0; i < IDEA_SET3_KEY.size(); ++i ) {
        auto idea = IDEA(unhexlify(IDEA_SET3_KEY[i]));
        EXPECT_EQ(hexlify(idea.encrypt(unhexlify(IDEA_SET3_PLAIN[i]))), IDEA_SET3_CIPHER[i]);
        EXPECT_EQ(hexlify(idea.decrypt(unhexlify(IDEA_SET3_CIPHER[i]))), IDEA_SET3_PLAIN[i]);
    }
}

TEST(IDEATest, test_idea_ecb_set4) {

    ASSERT_EQ(IDEA_SET4_KEY.size(), IDEA_SET4_PLAIN.size());
    ASSERT_EQ(IDEA_SET4_PLAIN.size(), IDEA_SET4_CIPHER.size());

    for ( unsigned int i = 0; i < IDEA_SET4_KEY.size(); ++i ) {
        auto idea = IDEA(unhexlify(IDEA_SET4_KEY[i]));
        EXPECT_EQ(hexlify(idea.encrypt(unhexlify(IDEA_SET4_PLAIN[i]))), IDEA_SET4_CIPHER[i]);
        EXPECT_EQ(hexlify(idea.decrypt(unhexlify(IDEA_SET4_CIPHER[i]))), IDEA_SET4_PLAIN[i]);
    }
}

TEST(IDEATest, test_idea_ecb_set5) {

    ASSERT_EQ(IDEA_SET5_KEY.size(), IDEA_SET5_PLAIN.size());

    const std::string UNHEX_IDEA_SET5_CIPHER = unhexlify(IDEA_SET5_CIPHER);

    for ( unsigned int i = 0; i < IDEA_SET5_KEY.size(); ++i ) {
        auto idea = IDEA(unhexlify(IDEA_SET5_KEY[i]));
        EXPECT_EQ(idea.encrypt(unhexlify(IDEA_SET5_PLAIN[i])), UNHEX_IDEA_SET5_CIPHER);
        EXPECT_EQ(hexlify(idea.decrypt(UNHEX_IDEA_SET5_CIPHER)), IDEA_SET5_PLAIN[i]);
    }
}

TEST(IDEATest, test_idea_ecb_set6) {

    ASSERT_EQ(IDEA_SET6_PLAIN.size(), IDEA_SET6_CIPHER.size());

    const std::string UNHEX_IDEA_SET6_KEY = unhexlify(IDEA_SET6_KEY);

    for ( unsigned int i = 0; i < IDEA_SET6_PLAIN.size(); ++i ) {
        auto idea = IDEA(UNHEX_IDEA_SET6_KEY);
        EXPECT_EQ(hexlify(idea.encrypt(unhexlify(IDEA_SET6_PLAIN[i]))), IDEA_SET6_CIPHER[i]);
        EXPECT_EQ(hexlify(idea.decrypt(unhexlify(IDEA_SET6_CIPHER[i]))), IDEA_SET6_PLAIN[i]);
    }
}

TEST(IDEATest, test_idea_ecb_set7) {

    ASSERT_EQ(IDEA_SET7_KEY.size(), IDEA_SET7_PLAIN.size());
    ASSERT_EQ(IDEA_SET7_PLAIN.size(), IDEA_SET7_CIPHER.size());

    for ( unsigned int i = 0; i < IDEA_SET7_KEY.size(); ++i ) {
        auto idea = IDEA(unhexlify(IDEA_SET7_KEY[i]));
        EXPECT_EQ(hexlify(idea.encrypt(unhexlify(IDEA_SET7_PLAIN[i]))), IDEA_SET7_CIPHER[i]);
        EXPECT_EQ(hexlify(idea.decrypt(unhexlify(IDEA_SET7_CIPHER[i]))), IDEA_SET7_PLAIN[i]);
    }
}

TEST(IDEATest, test_idea_ecb_set8) {

    ASSERT_EQ(IDEA_SET8_KEY.size(), IDEA_SET8_PLAIN.size());
    ASSERT_EQ(IDEA_SET8_PLAIN.size(), IDEA_SET8_CIPHER.size());

    for ( unsigned int i = 0; i < IDEA_SET8_KEY.size(); ++i ) {
        auto idea = IDEA(unhexlify(IDEA_SET8_KEY[i]));
        EXPECT_EQ(hexlify(idea.encrypt(unhexlify(IDEA_SET8_PLAIN[i]))), IDEA_SET8_CIPHER[i]);
        EXPECT_EQ(hexlify(idea.decrypt(unhexlify(IDEA_SET8_CIPHER[i]))), IDEA_SET8_PLAIN[i]);
    }
}

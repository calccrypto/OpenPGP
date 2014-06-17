#include <gtest/gtest.h>

#include "Encryptions/TDES.h"

#include "testvectors/tdes/tripledesecbinvperm.h"
#include "testvectors/tdes/tripledesecbpermop.h"
#include "testvectors/tdes/tripledesecbsubtab.h"
#include "testvectors/tdes/tripledesecbvarkey.h"
#include "testvectors/tdes/tripledesecbvartext.h"

TEST(TripleDESTest, test_tripledes_ecb_invperm) {

    ASSERT_EQ(TDES_ECB_INVPERM_PLAIN.size(), TDES_ECB_INVPERM_CIPHER.size());

    const std::string key = unhexlify(TDES_ECB_INVPERM_KEY);

    for ( unsigned int i = 0; i < TDES_ECB_INVPERM_PLAIN.size(); ++i ) {
        auto tdes = TDES(key, "e", key, "d", key, "e");  //!< DES(key) == TDES(key, key, key)
        EXPECT_EQ(hexlify(tdes.encrypt(unhexlify(TDES_ECB_INVPERM_PLAIN[i]))), TDES_ECB_INVPERM_CIPHER[i]);
        EXPECT_EQ(hexlify(tdes.decrypt(unhexlify(TDES_ECB_INVPERM_CIPHER[i]))), TDES_ECB_INVPERM_PLAIN[i]);
    }
}

TEST(TripleDESTest, test_tripledes_ecb_permop) {

    ASSERT_EQ(TDES_ECB_PERMOP_KEY.size(), TDES_ECB_PERMOP_CIPHER.size());

    const std::string UNHEX_TDES_ECB_PERMOP_PLAIN = unhexlify(TDES_ECB_PERMOP_PLAIN);

    for ( unsigned int i = 0; i < TDES_ECB_PERMOP_KEY.size(); ++i ) {
        std::string key = unhexlify(TDES_ECB_PERMOP_KEY[i]);
        auto tdes = TDES(key, "e", key, "d", key, "e");  //!< DES(key) == TDES(key, key, key)
        EXPECT_EQ(hexlify(tdes.encrypt(UNHEX_TDES_ECB_PERMOP_PLAIN)), TDES_ECB_PERMOP_CIPHER[i]);
        EXPECT_EQ(tdes.decrypt(unhexlify(TDES_ECB_PERMOP_CIPHER[i])), UNHEX_TDES_ECB_PERMOP_PLAIN);
    }
}

TEST(TripleDESTest, test_tripledes_ecb_subtab) {

    ASSERT_EQ(TDES_ECB_SUBTAB_KEY.size(), TDES_ECB_SUBTAB_PLAIN.size());
    ASSERT_EQ(TDES_ECB_SUBTAB_PLAIN.size(), TDES_ECB_SUBTAB_CIPHER.size());

    for ( unsigned int i = 0; i < TDES_ECB_SUBTAB_KEY.size(); ++i ) {
        std::string key = unhexlify(TDES_ECB_SUBTAB_KEY[i]);
        auto tdes = TDES(key, "e", key, "d", key, "e");  //!< DES(key) == TDES(key, key, key)
        EXPECT_EQ(hexlify(tdes.encrypt(unhexlify(TDES_ECB_SUBTAB_PLAIN[i]))), TDES_ECB_SUBTAB_CIPHER[i]);
        EXPECT_EQ(hexlify(tdes.decrypt(unhexlify(TDES_ECB_SUBTAB_CIPHER[i]))), TDES_ECB_SUBTAB_PLAIN[i]);
    }
}

TEST(TripleDESTest, test_tripledes_ecb_varkey) {

    ASSERT_EQ(TDES_ECB_VARKEY_KEY.size(), TDES_ECB_VARKEY_CIPHER.size());

    const std::string UNHEX_TDES_ECB_VARKEY_PLAIN = unhexlify(TDES_ECB_VARKEY_PLAIN);

    for ( unsigned int i = 0; i < TDES_ECB_VARKEY_KEY.size(); ++i ) {
        std::string key = unhexlify(TDES_ECB_VARKEY_KEY[i]);
        auto tdes = TDES(key, "e", key, "d", key, "e");  //!< DES(key) == TDES(key, key, key)
        EXPECT_EQ(hexlify(tdes.encrypt(UNHEX_TDES_ECB_VARKEY_PLAIN)), TDES_ECB_VARKEY_CIPHER[i]);
        EXPECT_EQ(tdes.decrypt(unhexlify(TDES_ECB_VARKEY_CIPHER[i])), UNHEX_TDES_ECB_VARKEY_PLAIN);
    }
}

TEST(TripleDESTest, test_tripledes_ecb_vartext) {

    ASSERT_EQ(TDES_ECB_VARTEXT_PLAIN.size(), TDES_ECB_VARTEXT_CIPHER.size());

    const std::string key = unhexlify(TDES_ECB_VARTEXT_KEY);

    for ( unsigned int i = 0; i < TDES_ECB_VARTEXT_PLAIN.size(); ++i ) {
        auto tdes = TDES(key, "e", key, "d", key, "e");  //!< DES(key) == TDES(key, key, key)
        EXPECT_EQ(hexlify(tdes.encrypt(unhexlify(TDES_ECB_VARTEXT_PLAIN[i]))), TDES_ECB_VARTEXT_CIPHER[i]);
        EXPECT_EQ(hexlify(tdes.decrypt(unhexlify(TDES_ECB_VARTEXT_CIPHER[i]))), TDES_ECB_VARTEXT_PLAIN[i]);
    }
}

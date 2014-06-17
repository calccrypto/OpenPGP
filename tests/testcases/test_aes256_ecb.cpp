#include <gtest/gtest.h>

#include "Encryptions/AES.h"

#include "testvectors/aes/aesecbgfsbox256.h"
#include "testvectors/aes/aesecbsbox256.h"
#include "testvectors/aes/aesecbvarkey256.h"
#include "testvectors/aes/aesecbvartxt256.h"

TEST(AESTest, test_aes256_ecb_gfsbox) {

    ASSERT_EQ(AES256_ECB_GFSBOX_PLAIN.size(), AES256_ECB_GFSBOX_CIPHER.size());

    const std::string UNHEX_AES256_ECB_GFSBOX_KEY = unhexlify(AES256_ECB_GFSBOX_KEY);

    for ( unsigned int i = 0; i < AES256_ECB_GFSBOX_PLAIN.size(); ++i ) {
        auto aes256 = AES(UNHEX_AES256_ECB_GFSBOX_KEY);
        EXPECT_EQ(hexlify(aes256.encrypt(unhexlify(AES256_ECB_GFSBOX_PLAIN[i]))), AES256_ECB_GFSBOX_CIPHER[i]);
        EXPECT_EQ(hexlify(aes256.decrypt(unhexlify(AES256_ECB_GFSBOX_CIPHER[i]))), AES256_ECB_GFSBOX_PLAIN[i]);
    }
}

TEST(AESTest, test_aes256_ecb_sbox) {

    ASSERT_EQ(AES256_ECB_SBOX_KEY.size(), AES256_ECB_SBOX_CIPHER.size());

    const std::string UNHEX_AES256_ECB_SBOX_PLAIN = unhexlify(AES256_ECB_SBOX_PLAIN);

    for ( unsigned int i = 0; i < AES256_ECB_SBOX_KEY.size(); ++i ) {
        auto aes256 = AES(unhexlify(AES256_ECB_SBOX_KEY[i]));
        EXPECT_EQ(hexlify(aes256.encrypt(UNHEX_AES256_ECB_SBOX_PLAIN)), AES256_ECB_SBOX_CIPHER[i]);
        EXPECT_EQ(aes256.decrypt(unhexlify(AES256_ECB_SBOX_CIPHER[i])), UNHEX_AES256_ECB_SBOX_PLAIN);
    }
}

TEST(AESTest, test_aes256_ecb_varkey) {

    ASSERT_EQ(AES256_ECB_VARKEY_KEY.size(), AES256_ECB_VARKEY_CIPHER.size());

    const std::string UNHEX_AES256_ECB_VARKEY_PLAIN = unhexlify(AES256_ECB_VARKEY_PLAIN);

    for ( unsigned int i = 0; i < AES256_ECB_VARKEY_KEY.size(); ++i ) {
        auto aes256 = AES(unhexlify(AES256_ECB_VARKEY_KEY[i]));
        EXPECT_EQ(hexlify(aes256.encrypt(UNHEX_AES256_ECB_VARKEY_PLAIN)), AES256_ECB_VARKEY_CIPHER[i]);
        EXPECT_EQ(aes256.decrypt(unhexlify(AES256_ECB_VARKEY_CIPHER[i])), UNHEX_AES256_ECB_VARKEY_PLAIN);
    }
}

TEST(AESTest, test_aes256_ecb_vartxt) {

    ASSERT_EQ(AES256_ECB_VARTXT_PLAIN.size(), AES256_ECB_VARTXT_CIPHER.size());

    const std::string UNHEX_AES256_ECB_VARTXT_KEY = unhexlify(AES256_ECB_VARTXT_KEY);

    for ( unsigned int i = 0; i < AES256_ECB_VARTXT_PLAIN.size(); ++i ) {
        auto aes256 = AES(UNHEX_AES256_ECB_VARTXT_KEY);
        EXPECT_EQ(hexlify(aes256.encrypt(unhexlify(AES256_ECB_VARTXT_PLAIN[i]))), AES256_ECB_VARTXT_CIPHER[i]);
        EXPECT_EQ(hexlify(aes256.decrypt(unhexlify(AES256_ECB_VARTXT_CIPHER[i]))), AES256_ECB_VARTXT_PLAIN[i]);
    }
}


#include <gtest/gtest.h>

#include "Encryptions/AES.h"

#include "testvectors/aes/aesecbgfsbox128.h"
#include "testvectors/aes/aesecbsbox128.h"
#include "testvectors/aes/aesecbvarkey128.h"
#include "testvectors/aes/aesecbvartxt128.h"

TEST(AESTest, test_aes128_ecb_gfsbox) {

    ASSERT_EQ(AES128_ECB_GFSBOX_PLAIN.size(), AES128_ECB_GFSBOX_CIPHER.size());

    const std::string UNHEX_AES128_ECB_GFSBOX_KEY = unhexlify(AES128_ECB_GFSBOX_KEY);

    for ( unsigned int i = 0; i < AES128_ECB_GFSBOX_PLAIN.size(); ++i ) {
        auto aes128 = AES(UNHEX_AES128_ECB_GFSBOX_KEY);
        EXPECT_EQ(hexlify(aes128.encrypt(unhexlify(AES128_ECB_GFSBOX_PLAIN[i]))), AES128_ECB_GFSBOX_CIPHER[i]);
        EXPECT_EQ(hexlify(aes128.decrypt(unhexlify(AES128_ECB_GFSBOX_CIPHER[i]))), AES128_ECB_GFSBOX_PLAIN[i]);
    }
}

TEST(AESTest, test_aes128_ecb_sbox) {

    ASSERT_EQ(AES128_ECB_SBOX_KEY.size(), AES128_ECB_SBOX_CIPHER.size());

    const std::string UNHEX_AES128_ECB_SBOX_PLAIN = unhexlify(AES128_ECB_SBOX_PLAIN);

    for ( unsigned int i = 0; i < AES128_ECB_SBOX_KEY.size(); ++i ) {
        auto aes128 = AES(unhexlify(AES128_ECB_SBOX_KEY[i]));
        EXPECT_EQ(hexlify(aes128.encrypt(UNHEX_AES128_ECB_SBOX_PLAIN)), AES128_ECB_SBOX_CIPHER[i]);
        EXPECT_EQ(aes128.decrypt(unhexlify(AES128_ECB_SBOX_CIPHER[i])), UNHEX_AES128_ECB_SBOX_PLAIN);
    }
}

TEST(AESTest, test_aes128_ecb_varkey) {

    ASSERT_EQ(AES128_ECB_VARKEY_KEY.size(), AES128_ECB_VARKEY_CIPHER.size());

    const std::string UNHEX_AES128_ECB_VARKEY_PLAIN = unhexlify(AES128_ECB_VARKEY_PLAIN);

    for ( unsigned int i = 0; i < AES128_ECB_VARKEY_KEY.size(); ++i ) {
        auto aes128 = AES(unhexlify(AES128_ECB_VARKEY_KEY[i]));
        EXPECT_EQ(hexlify(aes128.encrypt(UNHEX_AES128_ECB_VARKEY_PLAIN)), AES128_ECB_VARKEY_CIPHER[i]);
        EXPECT_EQ(aes128.decrypt(unhexlify(AES128_ECB_VARKEY_CIPHER[i])), UNHEX_AES128_ECB_VARKEY_PLAIN);
    }
}

TEST(AESTest, test_aes128_ecb_vartxt) {

    ASSERT_EQ(AES128_ECB_VARTXT_PLAIN.size(), AES128_ECB_VARTXT_CIPHER.size());

    const std::string UNHEX_AES128_ECB_VARTXT_KEY = unhexlify(AES128_ECB_VARTXT_KEY);

    for ( unsigned int i = 0; i < AES128_ECB_VARTXT_PLAIN.size(); ++i ) {
        auto aes128 = AES(UNHEX_AES128_ECB_VARTXT_KEY);
        EXPECT_EQ(hexlify(aes128.encrypt(unhexlify(AES128_ECB_VARTXT_PLAIN[i]))), AES128_ECB_VARTXT_CIPHER[i]);
        EXPECT_EQ(hexlify(aes128.decrypt(unhexlify(AES128_ECB_VARTXT_CIPHER[i]))), AES128_ECB_VARTXT_PLAIN[i]);
    }
}


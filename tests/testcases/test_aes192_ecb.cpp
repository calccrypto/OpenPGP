#include <gtest/gtest.h>

#include "Encryptions/AES.h"

#include "testvectors/aes/aesecbgfsbox192.h"
#include "testvectors/aes/aesecbsbox192.h"
#include "testvectors/aes/aesecbvarkey192.h"
#include "testvectors/aes/aesecbvartxt192.h"

TEST(AESTest, test_aes192_ecb_gfsbox) {

    ASSERT_EQ(AES192_ECB_GFSBOX_PLAIN.size(), AES192_ECB_GFSBOX_CIPHER.size());

    const std::string UNHEX_AES192_ECB_GFSBOX_KEY = unhexlify(AES192_ECB_GFSBOX_KEY);

    for ( unsigned int i = 0; i < AES192_ECB_GFSBOX_PLAIN.size(); ++i ) {
        auto aes192 = AES(UNHEX_AES192_ECB_GFSBOX_KEY);
        EXPECT_EQ(hexlify(aes192.encrypt(unhexlify(AES192_ECB_GFSBOX_PLAIN[i]))), AES192_ECB_GFSBOX_CIPHER[i]);
        EXPECT_EQ(hexlify(aes192.decrypt(unhexlify(AES192_ECB_GFSBOX_CIPHER[i]))), AES192_ECB_GFSBOX_PLAIN[i]);
    }
}

TEST(AESTest, test_aes192_ecb_sbox) {

    ASSERT_EQ(AES192_ECB_SBOX_KEY.size(), AES192_ECB_SBOX_CIPHER.size());

    const std::string UNHEX_AES192_ECB_SBOX_PLAIN = unhexlify(AES192_ECB_SBOX_PLAIN);

    for ( unsigned int i = 0; i < AES192_ECB_SBOX_KEY.size(); ++i ) {
        auto aes192 = AES(unhexlify(AES192_ECB_SBOX_KEY[i]));
        EXPECT_EQ(hexlify(aes192.encrypt(UNHEX_AES192_ECB_SBOX_PLAIN)), AES192_ECB_SBOX_CIPHER[i]);
        EXPECT_EQ(aes192.decrypt(unhexlify(AES192_ECB_SBOX_CIPHER[i])), UNHEX_AES192_ECB_SBOX_PLAIN);
    }
}

TEST(AESTest, test_aes192_ecb_varkey) {

    ASSERT_EQ(AES192_ECB_VARKEY_KEY.size(), AES192_ECB_VARKEY_CIPHER.size());

    const std::string UNHEX_AES192_ECB_VARKEY_PLAIN = unhexlify(AES192_ECB_VARKEY_PLAIN);

    for ( unsigned int i = 0; i < AES192_ECB_VARKEY_KEY.size(); ++i ) {
        auto aes192 = AES(unhexlify(AES192_ECB_VARKEY_KEY[i]));
        EXPECT_EQ(hexlify(aes192.encrypt(UNHEX_AES192_ECB_VARKEY_PLAIN)), AES192_ECB_VARKEY_CIPHER[i]);
        EXPECT_EQ(aes192.decrypt(unhexlify(AES192_ECB_VARKEY_CIPHER[i])), UNHEX_AES192_ECB_VARKEY_PLAIN);
    }
}

TEST(AESTest, test_aes192_ecb_vartxt) {

    ASSERT_EQ(AES192_ECB_VARTXT_PLAIN.size(), AES192_ECB_VARTXT_CIPHER.size());

    const std::string UNHEX_AES192_ECB_VARTXT_KEY = unhexlify(AES192_ECB_VARTXT_KEY);

    for ( unsigned int i = 0; i < AES192_ECB_VARTXT_PLAIN.size(); ++i ) {
        auto aes192 = AES(UNHEX_AES192_ECB_VARTXT_KEY);
        EXPECT_EQ(hexlify(aes192.encrypt(unhexlify(AES192_ECB_VARTXT_PLAIN[i]))), AES192_ECB_VARTXT_CIPHER[i]);
        EXPECT_EQ(hexlify(aes192.decrypt(unhexlify(AES192_ECB_VARTXT_CIPHER[i]))), AES192_ECB_VARTXT_PLAIN[i]);
    }
}


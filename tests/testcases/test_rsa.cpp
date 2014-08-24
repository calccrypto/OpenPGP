#include <gtest/gtest.h>

#include "sign.h"

#include "testvectors/rsa/rsasiggen15_186-2.h"

const uint8_t PKA_RSA = 1;

TEST(RSATest, test_rsa_sign_pkcs1_v1_5) {

    ASSERT_EQ(RSA_SIGGEN_N.size(), RSA_SIGGEN_D.size());

    auto e = hextompi(RSA_SIGGEN_E);
    for ( unsigned int i = 0; i < RSA_SIGGEN_N.size(); ++i ) {
        auto n = hextompi(RSA_SIGGEN_N[i]);
        auto d = hextompi(RSA_SIGGEN_D[i]);

        for ( unsigned int x = 0; x < RSA_SIGGEN_MSG[i].size(); ++x ) {
            auto msg = RSA_SIGGEN_MSG[i][x];
            int h = std::get<0>(msg);
            std::string data = unhexlify(std::get<1>(msg));
            std::string digest = use_hash(h, data);

            auto ret = pka_sign(digest, PKA_RSA, {n, e}, {d}, h);
            ASSERT_EQ(ret.size(), 1);
            EXPECT_EQ(mpitohex(ret[0]), RSA_SIGGEN_SIG[i][x]);
            EXPECT_TRUE(pka_verify(digest, h, PKA_RSA, {n, e}, {hextompi(RSA_SIGGEN_SIG[i][x])}));
        }
    }
}

TEST(RSATest, test_rsa_keygen) {
    std::vector <PGPMPI> key = RSA_keygen(512);
    std::vector <PGPMPI> pub = {key[0], key[1]};
    std::vector <PGPMPI> pri = {key[2]};

    PGPMPI message = rawtompi("The magic words are squeamish ossifrage\n");

    auto encrypted = RSA_encrypt(message, pub);
    auto decrypted = RSA_decrypt(encrypted, pri, pub);
    EXPECT_EQ(decrypted, message);

    auto signature = RSA_sign(message, pri, pub);
    EXPECT_TRUE(RSA_verify(message, {signature}, pub));
}

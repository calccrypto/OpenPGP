#include <gtest/gtest.h>

#include "sign.h"

#include "testvectors/rsa/rsasiggen15_186-2.h"

const uint8_t PKA_RSA = 1;

std::string to_hex(const mpz_class & mpi) {
    std::string out = mpi.get_str(16);
    out = ((out.size() & 1)?"0":"") + out;
    return out;
}

TEST(RSATest, test_rsa_sign_pkcs1_v1_5) {

    ASSERT_EQ(RSA_SIGGEN_N.size(), RSA_SIGGEN_D.size());

    auto e = mpz_class(RSA_SIGGEN_E, 16);
    for ( unsigned int i = 0; i < RSA_SIGGEN_N.size(); ++i ) {
        auto n = mpz_class(RSA_SIGGEN_N[i], 16);
        auto d = mpz_class(RSA_SIGGEN_D[i], 16);

        for ( unsigned int x = 0; x < RSA_SIGGEN_MSG[i].size(); ++x ) {
            auto msg = RSA_SIGGEN_MSG[i][x];
            int h = std::get<0>(msg);
            std::string data = unhexlify(std::get<1>(msg));
            std::string digest = use_hash(h, data);

            auto ret = pka_sign(digest, PKA_RSA, {n, e}, {d}, h);
            ASSERT_EQ(ret.size(), 1);
            EXPECT_EQ(to_hex(ret[0]), RSA_SIGGEN_SIG[i][x]);
            EXPECT_TRUE(pka_verify(digest, PKA_RSA, {n, e}, {mpz_class(RSA_SIGGEN_SIG[i][x], 16)}, h));
        }
    }
}

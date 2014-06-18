#include <gtest/gtest.h>

#include "sign.h"

#include "testvectors/dsa/dsasiggen.h"

const uint8_t PKA_DSA = 17;

TEST(DSATest, test_dsa_siggen) {

    ASSERT_EQ(DSA_SIGGEN_MSG.size(), DSA_SIGGEN_X.size());
    ASSERT_EQ(DSA_SIGGEN_X.size(), DSA_SIGGEN_Y.size());
    ASSERT_EQ(DSA_SIGGEN_Y.size(), DSA_SIGGEN_K.size());
    ASSERT_EQ(DSA_SIGGEN_K.size(), DSA_SIGGEN_R.size());
    ASSERT_EQ(DSA_SIGGEN_R.size(), DSA_SIGGEN_S.size());

    auto p = mpz_class(DSA_SIGGEN_P, 16);
    auto q = mpz_class(DSA_SIGGEN_Q, 16);
    auto g = mpz_class(DSA_SIGGEN_G, 16);
    for ( unsigned int i = 0; i < DSA_SIGGEN_MSG.size(); ++i ) {
        auto digest = SHA1(unhexlify(DSA_SIGGEN_MSG[i])).digest();
        auto x = mpz_class(DSA_SIGGEN_X[i], 16);
        auto y = mpz_class(DSA_SIGGEN_Y[i], 16);
        auto k = mpz_class(DSA_SIGGEN_K[i], 16);
        auto r = mpz_class(DSA_SIGGEN_R[i], 16);
        auto s = mpz_class(DSA_SIGGEN_S[i], 16);
        std::vector<mpz_class> sig = {r, s};
        EXPECT_EQ(DSA_sign(digest, {x}, {p, q, g, y}, k), sig);
        EXPECT_TRUE(pka_verify(digest, PKA_DSA, {p, q, g, y}, sig));

        //! test random k
        auto new_sig = pka_sign(digest, PKA_DSA, {p, q, g, y}, {x});
        EXPECT_NE(new_sig, sig);
        EXPECT_TRUE(pka_verify(digest, PKA_DSA, {p, q, g, y}, new_sig));
    }
}

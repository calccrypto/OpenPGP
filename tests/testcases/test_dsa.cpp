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

    auto p = hextompi(DSA_SIGGEN_P);
    auto q = hextompi(DSA_SIGGEN_Q);
    auto g = hextompi(DSA_SIGGEN_G);
    for ( unsigned int i = 0; i < DSA_SIGGEN_MSG.size(); ++i ) {
        auto digest = SHA1(unhexlify(DSA_SIGGEN_MSG[i])).digest();
        auto x = hextompi(DSA_SIGGEN_X[i]);
        auto y = hextompi(DSA_SIGGEN_Y[i]);
        auto k = hextompi(DSA_SIGGEN_K[i]);
        auto r = hextompi(DSA_SIGGEN_R[i]);
        auto s = hextompi(DSA_SIGGEN_S[i]);
        std::vector<PGPMPI> sig = {r, s};
        EXPECT_EQ(DSA_sign(digest, {x}, {p, q, g, y}, k), sig);
        EXPECT_TRUE(pka_verify(digest, 2, PKA_DSA, {p, q, g, y}, sig));

        //! test random k
        auto new_sig = pka_sign(digest, PKA_DSA, {p, q, g, y}, {x}, 2);
        EXPECT_NE(new_sig, sig);
        EXPECT_TRUE(pka_verify(digest, 2, PKA_DSA, {p, q, g, y}, new_sig));
    }
}

#include <gtest/gtest.h>

#include <set>
#include <utility>

#include "PKA/DSA.h"
#include "sign.h"

#include "testvectors/dsa/dsasiggen.h"

const uint8_t PKA_DSA = OpenPGP::PKA::ID::DSA;

TEST(DSA, dsa_siggen) {

    ASSERT_EQ(DSA_SIGGEN_MSG.size(), DSA_SIGGEN_X.size());
    ASSERT_EQ(DSA_SIGGEN_X.size(),   DSA_SIGGEN_Y.size());
    ASSERT_EQ(DSA_SIGGEN_Y.size(),   DSA_SIGGEN_K.size());
    ASSERT_EQ(DSA_SIGGEN_K.size(),   DSA_SIGGEN_R.size());
    ASSERT_EQ(DSA_SIGGEN_R.size(),   DSA_SIGGEN_S.size());

    auto p = OpenPGP::hextompi(DSA_SIGGEN_P);
    auto q = OpenPGP::hextompi(DSA_SIGGEN_Q);
    auto g = OpenPGP::hextompi(DSA_SIGGEN_G);
    for ( unsigned int i = 0; i < DSA_SIGGEN_MSG.size(); ++i ) {
        auto digest = OpenPGP::Hash::use(OpenPGP::Hash::ID::SHA1, unhexlify(DSA_SIGGEN_MSG[i]));
        auto x = OpenPGP::hextompi(DSA_SIGGEN_X[i]);
        auto y = OpenPGP::hextompi(DSA_SIGGEN_Y[i]);
        auto k = OpenPGP::hextompi(DSA_SIGGEN_K[i]);
        auto r = OpenPGP::hextompi(DSA_SIGGEN_R[i]);
        auto s = OpenPGP::hextompi(DSA_SIGGEN_S[i]);
        const OpenPGP::PKA::Values sig = {r, s};
        EXPECT_EQ(OpenPGP::PKA::DSA::sign(digest, {x}, {p, q, g, y}, k), sig);
        EXPECT_EQ(OpenPGP::Verify::with_pka(digest, OpenPGP::Hash::ID::SHA1, PKA_DSA, {p, q, g, y}, sig), true);

        //! test random k
        auto new_sig = OpenPGP::Sign::with_pka(digest, PKA_DSA, {x}, {p, q, g, y}, OpenPGP::Hash::ID::SHA1);
        EXPECT_NE(new_sig, sig);
        EXPECT_EQ(OpenPGP::Verify::with_pka(digest, OpenPGP::Hash::ID::SHA1, PKA_DSA, {p, q, g, y}, new_sig), true);
    }
}

TEST(DSA, keygen) {
    static const std::set <std::pair<uint32_t, uint32_t> > LN = {
        std::make_pair(1024, 160),
        std::make_pair(2048, 224),
        std::make_pair(2048, 256),
        std::make_pair(3072, 256),
    };

    static const std::string digest = OpenPGP::Hash::use(OpenPGP::Hash::ID::SHA1, unhexlify(DSA_SIGGEN_MSG[0]));

    for(std::pair <uint32_t, uint32_t> const & ln : LN) {
        OpenPGP::PKA::Values pub = OpenPGP::PKA::DSA::new_public(ln.first, ln.second);
        const OpenPGP::PKA::Values pri = OpenPGP::PKA::DSA::keygen(pub);
        const OpenPGP::PKA::Values sig = OpenPGP::PKA::DSA::sign(digest, pri, pub, 0);
        EXPECT_TRUE(OpenPGP::PKA::DSA::verify(digest, sig, pub));
    }
}

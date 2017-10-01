#include <gtest/gtest.h>

#include "sign.h"

#include "../testvectors/msg.h"
#include "testvectors/rsa/rsasiggen15_186-2.h"

const uint8_t PKA_RSA = OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN;

TEST(RSA, sign_pkcs1_v1_5) {

    ASSERT_EQ(RSA_SIGGEN_N.size(), RSA_SIGGEN_D.size());

    auto e = OpenPGP::hextompi(RSA_SIGGEN_E);
    for ( unsigned int i = 0; i < RSA_SIGGEN_N.size(); ++i ) {
        auto n = OpenPGP::hextompi(RSA_SIGGEN_N[i]);
        auto d = OpenPGP::hextompi(RSA_SIGGEN_D[i]);

        for ( unsigned int x = 0; x < RSA_SIGGEN_MSG[i].size(); ++x ) {
            auto msg = RSA_SIGGEN_MSG[i][x];
            int h = std::get<0>(msg);
            std::string data = unhexlify(std::get<1>(msg));
            std::string digest = OpenPGP::Hash::use(h, data);
            auto ret = OpenPGP::Sign::with_pka(digest, PKA_RSA, {d}, {n, e}, h);
            ASSERT_EQ(ret.size(), (std::size_t) 1);
            EXPECT_EQ(OpenPGP::mpitohex(ret[0]), RSA_SIGGEN_SIG[i][x]);
            EXPECT_EQ(OpenPGP::Verify::with_pka(digest, h, PKA_RSA, {n, e}, {OpenPGP::hextompi(RSA_SIGGEN_SIG[i][x])}), true);
        }
    }
}

TEST(RSA, keygen) {
    OpenPGP::PKA::Values key = OpenPGP::PKA::RSA::keygen(512);
    OpenPGP::PKA::Values pub = {key[0], key[1]};
    OpenPGP::PKA::Values pri = {key[2], key[3], key[4], key[5]};

    OpenPGP::MPI message = OpenPGP::rawtompi(MESSAGE);

    auto encrypted = OpenPGP::PKA::RSA::encrypt(message, pub);
    auto decrypted = OpenPGP::PKA::RSA::decrypt(encrypted, pri, pub);
    EXPECT_EQ(decrypted, message);

    auto signature = OpenPGP::PKA::RSA::sign(message, pri, pub);
    EXPECT_TRUE(OpenPGP::PKA::RSA::verify(message, {signature}, pub));
}

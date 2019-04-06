#include <gtest/gtest.h>

#include "PKA/PKAs.h"

TEST(PKA, can_encrypt) {
    EXPECT_TRUE (OpenPGP::PKA::can_encrypt(OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN));
    EXPECT_TRUE (OpenPGP::PKA::can_encrypt(OpenPGP::PKA::ID::RSA_ENCRYPT_ONLY));
    EXPECT_FALSE(OpenPGP::PKA::can_encrypt(OpenPGP::PKA::ID::RSA_SIGN_ONLY));
    EXPECT_TRUE (OpenPGP::PKA::can_encrypt(OpenPGP::PKA::ID::ELGAMAL));
    EXPECT_FALSE(OpenPGP::PKA::can_encrypt(OpenPGP::PKA::ID::DSA));
    #ifdef GPG_COMPATIBLE
    EXPECT_TRUE (OpenPGP::PKA::can_encrypt(OpenPGP::PKA::ID::ECDH));
    EXPECT_FALSE(OpenPGP::PKA::can_encrypt(OpenPGP::PKA::ID::ECDSA));
    EXPECT_FALSE(OpenPGP::PKA::can_encrypt(OpenPGP::PKA::ID::EdDSA));
    #endif
}

TEST(PKA, can_sign) {
    EXPECT_TRUE (OpenPGP::PKA::can_sign(OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN));
    EXPECT_FALSE(OpenPGP::PKA::can_sign(OpenPGP::PKA::ID::RSA_ENCRYPT_ONLY));
    EXPECT_TRUE (OpenPGP::PKA::can_sign(OpenPGP::PKA::ID::RSA_SIGN_ONLY));
    EXPECT_FALSE(OpenPGP::PKA::can_sign(OpenPGP::PKA::ID::ELGAMAL));
    EXPECT_TRUE (OpenPGP::PKA::can_sign(OpenPGP::PKA::ID::DSA));
    #ifdef GPG_COMPATIBLE
    EXPECT_FALSE(OpenPGP::PKA::can_sign(OpenPGP::PKA::ID::ECDH));
    EXPECT_TRUE (OpenPGP::PKA::can_sign(OpenPGP::PKA::ID::ECDSA));
    EXPECT_TRUE (OpenPGP::PKA::can_sign(OpenPGP::PKA::ID::EdDSA));
    #endif
}

TEST(PKA, is_RSA) {
    EXPECT_TRUE (OpenPGP::PKA::is_RSA(OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN));
    EXPECT_TRUE (OpenPGP::PKA::is_RSA(OpenPGP::PKA::ID::RSA_ENCRYPT_ONLY));
    EXPECT_TRUE (OpenPGP::PKA::is_RSA(OpenPGP::PKA::ID::RSA_SIGN_ONLY));
    EXPECT_FALSE(OpenPGP::PKA::is_RSA(OpenPGP::PKA::ID::ELGAMAL));
    EXPECT_FALSE(OpenPGP::PKA::is_RSA(OpenPGP::PKA::ID::DSA));
    #ifdef GPG_COMPATIBLE
    EXPECT_FALSE(OpenPGP::PKA::is_RSA(OpenPGP::PKA::ID::ECDH));
    EXPECT_FALSE(OpenPGP::PKA::is_RSA(OpenPGP::PKA::ID::ECDSA));
    EXPECT_FALSE(OpenPGP::PKA::is_RSA(OpenPGP::PKA::ID::EdDSA));
    #endif
}

static const OpenPGP::MPI data = OpenPGP::hextompi("f0e1d2c3b4a598");

TEST(PKA, generate_RSA) {
    const uint8_t pka = OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN;

    const OpenPGP::PKA::Params params = OpenPGP::PKA::generate_params(pka, 1024);
    ASSERT_EQ(params.size(), 1);

    OpenPGP::PKA::Values pri, pub;
    ASSERT_EQ(OpenPGP::PKA::generate_keypair(pka, params, pri, pub), pka);
    ASSERT_EQ(pri.size(), 4);
    ASSERT_EQ(pub.size(), 2);

    OpenPGP::MPI encrypted = OpenPGP::PKA::RSA::encrypt(data, pub);
    EXPECT_EQ(OpenPGP::PKA::RSA::decrypt(encrypted, pri, pub), data);

    const OpenPGP::MPI sig = OpenPGP::PKA::RSA::sign(data, pri, pub);
    EXPECT_TRUE(OpenPGP::PKA::RSA::verify(data, {sig}, pub));
}

TEST(PKA, generate_ElGamal) {
    const uint8_t pka = OpenPGP::PKA::ID::ELGAMAL;

    const OpenPGP::PKA::Params params = OpenPGP::PKA::generate_params(pka, 1024);
    ASSERT_EQ(params.size(), 1);

    OpenPGP::PKA::Values pri, pub;
    ASSERT_EQ(OpenPGP::PKA::generate_keypair(pka, params, pri, pub), pka);
    ASSERT_EQ(pri.size(), 1);
    ASSERT_EQ(pub.size(), 3);

    const OpenPGP::PKA::Values encrypted = OpenPGP::PKA::ElGamal::encrypt(data, pub);
    EXPECT_EQ(OpenPGP::PKA::ElGamal::decrypt(encrypted, pri, pub), OpenPGP::mpitoraw(data));
}

TEST(PKA, generate_DSA) {
    const uint8_t pka = OpenPGP::PKA::ID::DSA;

    // invalid size
    EXPECT_EQ(OpenPGP::PKA::generate_params(pka, 1023).size(), 0);

    const OpenPGP::PKA::Params params = OpenPGP::PKA::generate_params(pka, 1024);
    ASSERT_EQ(params.size(), 2);

    OpenPGP::PKA::Values pri, pub;
    ASSERT_EQ(OpenPGP::PKA::generate_keypair(pka, params, pri, pub), pka);
    ASSERT_EQ(pri.size(), 1);
    ASSERT_EQ(pub.size(), 4);

    const OpenPGP::PKA::Values sig = OpenPGP::PKA::DSA::sign(data, pri, pub);
    EXPECT_TRUE(OpenPGP::PKA::DSA::verify(data, sig, pub));
}

TEST(PKA, generate_bad) {
    const uint8_t pka = 0xff;

    // invalid pka
    const OpenPGP::PKA::Params params = OpenPGP::PKA::generate_params(pka, 1024);
    EXPECT_EQ(params.size(), 0);

    // pass size check, but fail pka check
    OpenPGP::PKA::Values pri, pub;
    EXPECT_EQ(OpenPGP::PKA::generate_keypair(pka, {0}, pri, pub), 0);
    EXPECT_EQ(pri.size(), 0);
    EXPECT_EQ(pub.size(), 0);
}

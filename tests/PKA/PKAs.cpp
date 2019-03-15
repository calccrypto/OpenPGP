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

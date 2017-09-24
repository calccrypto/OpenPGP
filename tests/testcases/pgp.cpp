#include <iostream>
#include <ctime>
#include <sstream>

#include <gtest/gtest.h>

#include "decrypt.h"
#include "encrypt.h"
#include "generatekey.h"
#include "revoke.h"
#include "sign.h"
#include "verify.h"

#include "testvectors/msg.h"
#include "testvectors/pass.h"
#include "testvectors/read_pgp.h"

TEST(PGP, keygen){

    KeyGen config;

    // no starting user ID packet
    EXPECT_EQ(config.valid(), false);
    config.uids.push_back(KeyGen::UserID());
    EXPECT_EQ(config.valid(), true);

    // PKA
    config.pka = 255;                           // invalid PKA
    EXPECT_EQ(config.valid(), false);
    for(std::pair <std::string const, uint8_t> const & pka : PKA::NUMBER){
        config.pka = pka.second;
        EXPECT_EQ(config.valid(), PKA::can_sign(config.pka));
    }
    config.pka = PKA::RSA_ENCRYPT_OR_SIGN;

    // Sym
    config.sym = 255;                           // invalid Sym
    EXPECT_EQ(config.valid(), false);
    for(std::pair <std::string const, uint8_t> const & sym : Sym::NUMBER){
        config.sym = sym.second;                // valid Sym
        EXPECT_EQ(config.valid(), true);
    }
    config.sym = Sym::AES256;

    // Hash
    config.hash = 255;                          // invalid Hash
    EXPECT_EQ(config.valid(), false);
    for(std::pair <std::string const, uint8_t> const & hash : Hash::NUMBER){
        config.hash = hash.second;              // valid Hash
        EXPECT_EQ(config.valid(), true);
    }
    config.sym = Hash::SHA256;

    // add subkey
    config.subkeys.push_back(KeyGen::SubkeyGen());
    EXPECT_EQ(config.valid(), true);

    // subkey PKA
    config.subkeys[0].pka = 255;                // invalid PKA
    EXPECT_EQ(config.valid(), false);
    for(std::pair <std::string const, uint8_t> const & pka : PKA::NUMBER){
        config.subkeys[0].pka = pka.second;
        EXPECT_EQ(config.valid(), true);
    }
    config.subkeys[0].pka = PKA::RSA_ENCRYPT_OR_SIGN;

    // subkey Sym
    config.subkeys[0].sym = 255;                // invalid Sym
    EXPECT_EQ(config.valid(), false);
    for(std::pair <std::string const, uint8_t> const & sym : Sym::NUMBER){
        config.subkeys[0].sym = sym.second;     // valid Sym
        EXPECT_EQ(config.valid(), true);
    }
    config.subkeys[0].sym = Sym::AES256;

    // subkey S2K Hash
    config.subkeys[0].hash = 255;               // invalid s2k Hash
    EXPECT_EQ(config.valid(), false);
    for(std::pair <std::string const, uint8_t> const & hash : Hash::NUMBER){
        config.subkeys[0].hash = hash.second;   // valid s2k Hash
        EXPECT_EQ(config.valid(), true);
    }
    config.subkeys[0].hash = Hash::SHA256;

    // subkey signing Hash
    config.subkeys[0].sig = 255;               // invalid signing Hash
    EXPECT_EQ(config.valid(), false);
    for(std::pair <std::string const, uint8_t> const & hash : Hash::NUMBER){
        config.subkeys[0].sig = hash.second;   // valid signing Hash
        EXPECT_EQ(config.valid(), true);
    }
    config.subkeys[0].sig = Hash::SHA256;

    EXPECT_EQ(config.valid(), true);

    // generate private key
    const PGPSecretKey pri = generate_key(config);
    EXPECT_EQ(pri.meaningful(), true);

    // extract public key from private
    const PGPPublicKey pub = pri.get_public();
    EXPECT_EQ(pub.meaningful(), true);

    EXPECT_EQ(pri.keyid(), pub.keyid());
    EXPECT_EQ(pri.fingerprint(), pub.fingerprint());
}

TEST(PGP, revoke_key){

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    const RevArgs revargs(pri, PASSPHRASE, pri);
    const PGPRevocationCertificate rev = revoke_key_cert(revargs);
    ASSERT_EQ(rev.meaningful(), true);

    // make sure that the revocation certificate generated is for this key
    EXPECT_EQ(verify_revoke(pri, rev), true);

    // revoke the key and make sure the returned public key is revoked
    const PGPPublicKey revpub = revoke_with_cert(pri, rev);
    EXPECT_EQ(revpub.meaningful(), true);
    EXPECT_EQ(check_revoked(revpub), true);

    // revoke directly on the key and make sure it is revoked
    const PGPPublicKey dirrevpub = revoke_key(revargs);
    EXPECT_EQ(dirrevpub.meaningful(), true);
    EXPECT_EQ(check_revoked(dirrevpub), true);
}

TEST(PGP, revoke_subkey){

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    const RevArgs revargs(pri, PASSPHRASE, pri);
    const PGPRevocationCertificate rev = revoke_subkey_cert(revargs, unhexlify("d27061e1"));
    rev.meaningful();
    ASSERT_EQ(rev.meaningful(), true);

    // make sure that the revocation certificate generated is for this key
    EXPECT_EQ(verify_revoke(pri, rev), true);

    // revoke the subkey and make sure the returned public key is revoked
    const PGPPublicKey revsub = revoke_with_cert(pri, rev);
    EXPECT_EQ(revsub.meaningful(), true);
    EXPECT_EQ(check_revoked(revsub), true);

    // revoke directly on the key and make sure it is revoked
    const PGPPublicKey dirrevsub = revoke_subkey(revargs, unhexlify("d27061e1"));
    EXPECT_EQ(dirrevsub.meaningful(), true);
    EXPECT_EQ(check_revoked(dirrevsub), true);
}

TEST(PGP, revoke_uid){

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    const RevArgs revargs(pri, PASSPHRASE, pri);
    const PGPRevocationCertificate rev = revoke_uid_cert(revargs, "alice");
    ASSERT_EQ(rev.meaningful(), true);

    // make sure that the revocation certificate generated is for this key
    EXPECT_EQ(verify_revoke(pri, rev), true);

    // revoke the uid and make sure the returned public key is revoked
    const PGPPublicKey revuid = revoke_with_cert(pri, rev);
    EXPECT_EQ(revuid.meaningful(), true);
    EXPECT_EQ(check_revoked(revuid), true);

    // revoke directly on the key and make sure it is revoked
    const PGPPublicKey dirrevuid = revoke_uid(revargs, "alice");
    EXPECT_EQ(dirrevuid.meaningful(), true);
    EXPECT_EQ(check_revoked(dirrevuid), true);
}

TEST(PGP, encrypt_decrypt_pka_mdc){

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    const EncryptArgs encrypt_args("", MESSAGE);
    const PGPMessage encrypted = encrypt_pka(encrypt_args, pri);
    EXPECT_EQ(encrypted.meaningful(), true);

    const PGP::Packets packets = encrypted.get_packets();
    EXPECT_EQ(packets[0] -> get_tag(), Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY);
    EXPECT_EQ(packets[1] -> get_tag(), Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA);

    const Tag1::Ptr tag1  = std::dynamic_pointer_cast <Tag1> (packets[0]);
    EXPECT_EQ(tag1 -> get_version(), (uint8_t) 3);
    EXPECT_EQ(tag1 -> get_keyid(), pri.keyid());
    EXPECT_EQ(tag1 -> get_pka(), PKA::RSA_ENCRYPT_OR_SIGN);
    EXPECT_EQ(tag1 -> get_mpi().size(), (PKA::Values::size_type) 1);

    const PGPMessage decrypted = decrypt_pka(pri, PASSPHRASE, encrypted);
    std::string message = "";
    for(Packet::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == Packet::LITERAL_DATA){
            message += std::dynamic_pointer_cast <Tag11> (p) -> out(false);
        }
    }
    EXPECT_EQ(message, MESSAGE);
}

TEST(PGP, encrypt_decrypt_pka_no_mdc){

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    EncryptArgs encrypt_args;
    encrypt_args.data = MESSAGE;
    encrypt_args.mdc = false;

    const PGPMessage encrypted = encrypt_pka(encrypt_args, pri);
    EXPECT_EQ(encrypted.meaningful(), true);

    const PGP::Packets packets = encrypted.get_packets();
    EXPECT_EQ(packets[0] -> get_tag(), Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY);
    EXPECT_EQ(packets[1] -> get_tag(), Packet::SYMMETRICALLY_ENCRYPTED_DATA);

    Tag1::Ptr tag1 = std::dynamic_pointer_cast <Tag1> (packets[0]);
    EXPECT_EQ(tag1 -> get_version(), (uint8_t) 3);
    EXPECT_EQ(tag1 -> get_keyid(), pri.keyid());
    EXPECT_EQ(tag1 -> get_pka(), PKA::RSA_ENCRYPT_OR_SIGN);
    EXPECT_EQ(tag1 -> get_mpi().size(), (PKA::Values::size_type) 1);

    const PGPMessage decrypted = decrypt_pka(pri, PASSPHRASE, encrypted);
    std::string message = "";
    for(Packet::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == Packet::LITERAL_DATA){
            message += std::dynamic_pointer_cast <Tag11> (p) -> out(false);
        }
    }
    EXPECT_EQ(message, MESSAGE);
}

TEST(PGP, encrypt_decrypt_symmetric_mdc){

    const EncryptArgs encrypt_args("", MESSAGE);
    const PGPMessage encrypted = encrypt_sym(encrypt_args, PASSPHRASE, Sym::AES256);
    EXPECT_EQ(encrypted.meaningful(), true);

    const PGP::Packets packets = encrypted.get_packets();
    EXPECT_EQ(packets[0] -> get_tag(), Packet::SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY);
    EXPECT_EQ(packets[1] -> get_tag(), Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA);

    const Tag3::Ptr tag3  = std::dynamic_pointer_cast <Tag3>  (packets[0]);
    EXPECT_EQ(tag3 -> get_version(), (uint8_t) 4);

    const PGPMessage decrypted = decrypt_sym(encrypted, PASSPHRASE);
    std::string message = "";
    for(Packet::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == Packet::LITERAL_DATA){
            message += std::dynamic_pointer_cast <Tag11> (p) -> out(false);
        }
    }
    EXPECT_EQ(message, MESSAGE);
}

TEST(PGP, encrypt_decrypt_symmetric_no_mdc){

    EncryptArgs encrypt_args;
    encrypt_args.data = MESSAGE;
    encrypt_args.mdc = false;

    const PGPMessage encrypted = encrypt_sym(encrypt_args, PASSPHRASE, Sym::AES256);
    EXPECT_EQ(encrypted.meaningful(), true);

    const PGP::Packets packets = encrypted.get_packets();
    EXPECT_EQ(packets[0] -> get_tag(), Packet::SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY);
    EXPECT_EQ(packets[1] -> get_tag(), Packet::SYMMETRICALLY_ENCRYPTED_DATA);

    const Tag3::Ptr tag3 = std::dynamic_pointer_cast <Tag3> (packets[0]);
    EXPECT_EQ(tag3 -> get_version(), (uint8_t) 4);

    const PGPMessage decrypted = decrypt_sym(encrypted, PASSPHRASE);
    std::string message = "";
    for(Packet::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == Packet::LITERAL_DATA){
            message += std::dynamic_pointer_cast <Tag11> (p) -> out(false);
        }
    }
    EXPECT_EQ(message, MESSAGE);
}

TEST(PGP, encrypt_sign_decrypt_verify){

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    EncryptArgs encrypt_args;
    encrypt_args.data = MESSAGE;
    encrypt_args.signer = std::make_shared <PGPSecretKey> (pri);
    encrypt_args.passphrase = PASSPHRASE;

    const PGPMessage encrypted = encrypt_pka(encrypt_args, pri);
    EXPECT_EQ(encrypted.meaningful(), true);

    const PGP::Packets packets = encrypted.get_packets();
    EXPECT_EQ(packets[0] -> get_tag(), Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY);
    EXPECT_EQ(packets[1] -> get_tag(), Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA);

    const Tag1::Ptr tag1  = std::dynamic_pointer_cast <Tag1> (packets[0]);
    EXPECT_EQ(tag1 -> get_version(), (uint8_t) 3);
    EXPECT_EQ(tag1 -> get_keyid(), pri.keyid());
    EXPECT_EQ(tag1 -> get_pka(), PKA::RSA_ENCRYPT_OR_SIGN);
    EXPECT_EQ(tag1 -> get_mpi().size(), (PKA::Values::size_type) 1);

    const PGPMessage decrypted = decrypt_pka(pri, PASSPHRASE, encrypted);
    std::string message = "";
    for(Packet::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == Packet::LITERAL_DATA){
            message += std::dynamic_pointer_cast <Tag11> (p) -> out(false);
        }
    }
    EXPECT_EQ(message, MESSAGE);

    EXPECT_EQ(verify_binary(pri, decrypted), true);
}

TEST(PGP, sign_verify_detached){

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    const SignArgs sign_args(pri, PASSPHRASE);
    const PGPDetachedSignature sig = sign_detached_signature(sign_args, MESSAGE);
    EXPECT_EQ(verify_detached_signature(pri, MESSAGE, sig), true);
}

TEST(PGP, sign_verify_binary){

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    const SignArgs sign_args(pri, PASSPHRASE);
    const PGPMessage sig = sign_binary(sign_args, "", MESSAGE, Compression::ZLIB);
    EXPECT_EQ(verify_binary(pri, sig), true);
}

TEST(PGP, sign_verify_cleartext){

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    const SignArgs sign_args(pri, PASSPHRASE);
    const PGPCleartextSignature sig = sign_cleartext_signature(sign_args, MESSAGE);
    EXPECT_EQ(verify_cleartext_signature(pri, sig), true);
}

TEST(PGP, verify_primary_key){

    PGPPublicKey pub;
    ASSERT_EQ(read_pgp <PGPPublicKey> ("Alicepub", pub), true);

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    EXPECT_EQ(verify_primary_key(pub, pub), true);
    EXPECT_EQ(verify_primary_key(pub, pri), true);
    EXPECT_EQ(verify_primary_key(pri, pub), true);
    EXPECT_EQ(verify_primary_key(pri, pri), true);
}
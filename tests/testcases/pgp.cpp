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

    OpenPGP::KeyGen config;

    // no starting user ID packet
    EXPECT_EQ(config.valid(), false);
    config.uids.push_back(OpenPGP::KeyGen::UserID());
    EXPECT_EQ(config.valid(), true);

    // PKA
    config.pka = 255;                           // invalid PKA
    EXPECT_EQ(config.valid(), false);
    for(std::pair <std::string const, uint8_t> const & pka : OpenPGP::PKA::NUMBER){
        // gpg only allows for RSA and DSA in the primary key
        #ifdef GPG_COMPATIBLE
        if (pka.second == OpenPGP::PKA::ID::ELGAMAL){
            continue;
        }
        #endif

        config.pka = pka.second;
        EXPECT_EQ(config.valid(), OpenPGP::PKA::can_sign(config.pka));
    }
    config.pka = OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN;

    // Sym
    config.sym = 255;                           // invalid Sym
    EXPECT_EQ(config.valid(), false);
    for(std::pair <std::string const, uint8_t> const & sym : OpenPGP::Sym::NUMBER){
        config.sym = sym.second;                // valid Sym
        EXPECT_EQ(config.valid(), true);
    }
    config.sym = OpenPGP::Sym::ID::AES256;

    // Hash
    config.hash = 255;                          // invalid Hash
    EXPECT_EQ(config.valid(), false);
    for(std::pair <std::string const, uint8_t> const & hash : OpenPGP::Hash::NUMBER){
        config.hash = hash.second;              // valid Hash
        EXPECT_EQ(config.valid(), true);
    }
    config.sym = OpenPGP::Hash::ID::SHA256;

    // add subkey
    config.subkeys.push_back(OpenPGP::KeyGen::SubkeyGen());
    EXPECT_EQ(config.valid(), true);

    // subkey PKA
    config.subkeys[0].pka = 255;                // invalid PKA
    EXPECT_EQ(config.valid(), false);
    for(std::pair <std::string const, uint8_t> const & pka : OpenPGP::PKA::NUMBER){
        config.subkeys[0].pka = pka.second;     // valid PKA
        EXPECT_EQ(config.valid(), true);
    }
    config.subkeys[0].pka = OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN;

    // subkey Sym
    config.subkeys[0].sym = 255;                // invalid Sym
    EXPECT_EQ(config.valid(), false);
    for(std::pair <std::string const, uint8_t> const & sym : OpenPGP::Sym::NUMBER){
        config.subkeys[0].sym = sym.second;     // valid Sym
        EXPECT_EQ(config.valid(), true);
    }
    config.subkeys[0].sym = OpenPGP::Sym::ID::AES256;

    // subkey S2K Hash
    config.subkeys[0].hash = 255;               // invalid s2k Hash
    EXPECT_EQ(config.valid(), false);
    for(std::pair <std::string const, uint8_t> const & hash : OpenPGP::Hash::NUMBER){
        config.subkeys[0].hash = hash.second;   // valid s2k Hash
        EXPECT_EQ(config.valid(), true);
    }
    config.subkeys[0].hash = OpenPGP::Hash::ID::SHA256;

    // subkey signing Hash
    config.subkeys[0].sig = 255;               // invalid signing Hash
    EXPECT_EQ(config.valid(), false);
    for(std::pair <std::string const, uint8_t> const & hash : OpenPGP::Hash::NUMBER){
        config.subkeys[0].sig = hash.second;   // valid signing Hash
        EXPECT_EQ(config.valid(), true);
    }
    config.subkeys[0].sig = OpenPGP::Hash::ID::SHA256;

    EXPECT_EQ(config.valid(), true);

    // generate private key
    const OpenPGP::SecretKey pri = generate_key(config);
    EXPECT_EQ(pri.meaningful(), true);

    // extract public key from private
    const OpenPGP::PublicKey pub = pri.get_public();
    EXPECT_EQ(pub.meaningful(), true);

    EXPECT_EQ(pri.keyid(), pub.keyid());
    EXPECT_EQ(pri.fingerprint(), pub.fingerprint());
}

TEST(PGP, revoke_key){

    OpenPGP::SecretKey pri;
    ASSERT_EQ(read_pgp <OpenPGP::SecretKey> ("Alicepri", pri), true);

    const OpenPGP::Revoke::Args revargs(pri, PASSPHRASE, pri);
    const OpenPGP::RevocationCertificate rev = OpenPGP::Revoke::key_cert(revargs);
    ASSERT_EQ(rev.meaningful(), true);

    // make sure that the revocation certificate generated is for this key
    EXPECT_EQ(OpenPGP::Verify::revoke(pri, rev), true);

    // revoke the key and make sure the returned public key is revoked
    const OpenPGP::PublicKey revpub = OpenPGP::Revoke::with_cert(pri, rev);
    EXPECT_EQ(revpub.meaningful(), true);
    EXPECT_EQ(OpenPGP::Revoke::check(revpub), true);

    // revoke directly on the key and make sure it is revoked
    const OpenPGP::PublicKey dirrevpub = OpenPGP::Revoke::key(revargs);
    EXPECT_EQ(dirrevpub.meaningful(), true);
    EXPECT_EQ(OpenPGP::Revoke::check(dirrevpub), true);
}

TEST(PGP, revoke_subkey){

    OpenPGP::SecretKey pri;
    ASSERT_EQ(read_pgp <OpenPGP::SecretKey> ("Alicepri", pri), true);

    const OpenPGP::Revoke::Args revargs(pri, PASSPHRASE, pri);
    const OpenPGP::RevocationCertificate rev = OpenPGP::Revoke::subkey_cert(revargs, unhexlify("d27061e1"));
    rev.meaningful();
    ASSERT_EQ(rev.meaningful(), true);

    // make sure that the revocation certificate generated is for this key
    EXPECT_EQ(OpenPGP::Verify::revoke(pri, rev), true);

    // revoke the subkey and make sure the returned public key is revoked
    const OpenPGP::PublicKey revsub = OpenPGP::Revoke::with_cert(pri, rev);
    EXPECT_EQ(revsub.meaningful(), true);
    EXPECT_EQ(OpenPGP::Revoke::check(revsub), true);

    // revoke directly on the key and make sure it is revoked
    const OpenPGP::PublicKey dirrevsub = OpenPGP::Revoke::subkey(revargs, unhexlify("d27061e1"));
    EXPECT_EQ(dirrevsub.meaningful(), true);
    EXPECT_EQ(OpenPGP::Revoke::check(dirrevsub), true);
}

TEST(PGP, revoke_uid){

    OpenPGP::SecretKey pri;
    ASSERT_EQ(read_pgp <OpenPGP::SecretKey> ("Alicepri", pri), true);

    const OpenPGP::Revoke::Args revargs(pri, PASSPHRASE, pri);
    const OpenPGP::RevocationCertificate rev = OpenPGP::Revoke::uid_cert(revargs, "alice");
    ASSERT_EQ(rev.meaningful(), true);

    // make sure that the revocation certificate generated is for this key
    EXPECT_EQ(OpenPGP::Verify::revoke(pri, rev), true);

    // revoke the uid and make sure the returned public key is revoked
    const OpenPGP::PublicKey revuid = OpenPGP::Revoke::with_cert(pri, rev);
    EXPECT_EQ(revuid.meaningful(), true);
    EXPECT_EQ(OpenPGP::Revoke::check(revuid), true);

    // revoke directly on the key and make sure it is revoked
    const OpenPGP::PublicKey dirrevuid = OpenPGP::Revoke::uid(revargs, "alice");
    EXPECT_EQ(dirrevuid.meaningful(), true);
    EXPECT_EQ(OpenPGP::Revoke::check(dirrevuid), true);
}

TEST(PGP, encrypt_decrypt_pka_mdc){

    OpenPGP::SecretKey pri;
    ASSERT_EQ(read_pgp <OpenPGP::SecretKey> ("Alicepri", pri), true);

    const OpenPGP::Encrypt::Args encrypt_args("", MESSAGE);
    const OpenPGP::Message encrypted = OpenPGP::Encrypt::pka(encrypt_args, pri);
    EXPECT_EQ(encrypted.meaningful(), true);

    const OpenPGP::PGP::Packets packets = encrypted.get_packets();
    EXPECT_EQ(packets[0] -> get_tag(), OpenPGP::Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY);
    EXPECT_EQ(packets[1] -> get_tag(), OpenPGP::Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA);

    const OpenPGP::Packet::Tag1::Ptr tag1  = std::dynamic_pointer_cast <OpenPGP::Packet::Tag1> (packets[0]);
    EXPECT_EQ(tag1 -> get_version(), (uint8_t) 3);
    EXPECT_EQ(tag1 -> get_keyid(), pri.keyid());
    EXPECT_EQ(tag1 -> get_pka(), OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN);
    EXPECT_EQ(tag1 -> get_mpi().size(), (OpenPGP::PKA::Values::size_type) 1);

    const OpenPGP::Message decrypted = OpenPGP::Decrypt::pka(pri, PASSPHRASE, encrypted);
    std::string message = "";
    for(OpenPGP::Packet::Tag::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == OpenPGP::Packet::LITERAL_DATA){
            message += std::dynamic_pointer_cast <OpenPGP::Packet::Tag11> (p) -> out(false);
        }
    }
    EXPECT_EQ(message, MESSAGE);
}

TEST(PGP, encrypt_decrypt_pka_no_mdc){

    OpenPGP::SecretKey pri;
    ASSERT_EQ(read_pgp <OpenPGP::SecretKey> ("Alicepri", pri), true);

    OpenPGP::Encrypt::Args encrypt_args;
    encrypt_args.data = MESSAGE;
    encrypt_args.mdc = false;

    const OpenPGP::Message encrypted = OpenPGP::Encrypt::pka(encrypt_args, pri);
    EXPECT_EQ(encrypted.meaningful(), true);

    const OpenPGP::PGP::Packets packets = encrypted.get_packets();
    EXPECT_EQ(packets[0] -> get_tag(), OpenPGP::Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY);
    EXPECT_EQ(packets[1] -> get_tag(), OpenPGP::Packet::SYMMETRICALLY_ENCRYPTED_DATA);

    OpenPGP::Packet::Tag1::Ptr tag1 = std::dynamic_pointer_cast <OpenPGP::Packet::Tag1> (packets[0]);
    EXPECT_EQ(tag1 -> get_version(), (uint8_t) 3);
    EXPECT_EQ(tag1 -> get_keyid(), pri.keyid());
    EXPECT_EQ(tag1 -> get_pka(), OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN);
    EXPECT_EQ(tag1 -> get_mpi().size(), (OpenPGP::PKA::Values::size_type) 1);

    const OpenPGP::Message decrypted = OpenPGP::Decrypt::pka(pri, PASSPHRASE, encrypted);
    std::string message = "";
    for(OpenPGP::Packet::Tag::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == OpenPGP::Packet::LITERAL_DATA){
            message += std::dynamic_pointer_cast <OpenPGP::Packet::Tag11> (p) -> out(false);
        }
    }
    EXPECT_EQ(message, MESSAGE);
}

TEST(PGP, encrypt_decrypt_symmetric_mdc){

    const OpenPGP::Encrypt::Args encrypt_args("", MESSAGE);
    const OpenPGP::Message encrypted = OpenPGP::Encrypt::sym(encrypt_args, PASSPHRASE, OpenPGP::Sym::ID::AES256);
    EXPECT_EQ(encrypted.meaningful(), true);

    const OpenPGP::PGP::Packets packets = encrypted.get_packets();
    EXPECT_EQ(packets[0] -> get_tag(), OpenPGP::Packet::SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY);
    EXPECT_EQ(packets[1] -> get_tag(), OpenPGP::Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA);

    const OpenPGP::Packet::Tag3::Ptr tag3  = std::dynamic_pointer_cast <OpenPGP::Packet::Tag3>  (packets[0]);
    EXPECT_EQ(tag3 -> get_version(), (uint8_t) 4);

    const OpenPGP::Message decrypted = OpenPGP::Decrypt::sym(encrypted, PASSPHRASE);
    std::string message = "";
    for(OpenPGP::Packet::Tag::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == OpenPGP::Packet::LITERAL_DATA){
            message += std::dynamic_pointer_cast <OpenPGP::Packet::Tag11> (p) -> out(false);
        }
    }
    EXPECT_EQ(message, MESSAGE);
}

TEST(PGP, encrypt_decrypt_symmetric_no_mdc){

    OpenPGP::Encrypt::Args encrypt_args;
    encrypt_args.data = MESSAGE;
    encrypt_args.mdc = false;

    const OpenPGP::Message encrypted = OpenPGP::Encrypt::sym(encrypt_args, PASSPHRASE, OpenPGP::Sym::ID::AES256);
    EXPECT_EQ(encrypted.meaningful(), true);

    const OpenPGP::PGP::Packets packets = encrypted.get_packets();
    EXPECT_EQ(packets[0] -> get_tag(), OpenPGP::Packet::SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY);
    EXPECT_EQ(packets[1] -> get_tag(), OpenPGP::Packet::SYMMETRICALLY_ENCRYPTED_DATA);

    const OpenPGP::Packet::Tag3::Ptr tag3 = std::dynamic_pointer_cast <OpenPGP::Packet::Tag3> (packets[0]);
    EXPECT_EQ(tag3 -> get_version(), (uint8_t) 4);

    const OpenPGP::Message decrypted = OpenPGP::Decrypt::sym(encrypted, PASSPHRASE);
    std::string message = "";
    for(OpenPGP::Packet::Tag::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == OpenPGP::Packet::LITERAL_DATA){
            message += std::dynamic_pointer_cast <OpenPGP::Packet::Tag11> (p) -> out(false);
        }
    }
    EXPECT_EQ(message, MESSAGE);
}

TEST(PGP, encrypt_sign_decrypt_verify){

    OpenPGP::SecretKey pri;
    ASSERT_EQ(read_pgp <OpenPGP::SecretKey> ("Alicepri", pri), true);

    OpenPGP::Encrypt::Args encrypt_args;
    encrypt_args.data = MESSAGE;
    encrypt_args.signer = std::make_shared <OpenPGP::SecretKey> (pri);
    encrypt_args.passphrase = PASSPHRASE;

    const OpenPGP::Message encrypted = OpenPGP::Encrypt::pka(encrypt_args, pri);
    EXPECT_EQ(encrypted.meaningful(), true);

    const OpenPGP::PGP::Packets packets = encrypted.get_packets();
    EXPECT_EQ(packets[0] -> get_tag(), OpenPGP::Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY);
    EXPECT_EQ(packets[1] -> get_tag(), OpenPGP::Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA);

    const OpenPGP::Packet::Tag1::Ptr tag1  = std::dynamic_pointer_cast <OpenPGP::Packet::Tag1> (packets[0]);
    EXPECT_EQ(tag1 -> get_version(), (uint8_t) 3);
    EXPECT_EQ(tag1 -> get_keyid(), pri.keyid());
    EXPECT_EQ(tag1 -> get_pka(), OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN);
    EXPECT_EQ(tag1 -> get_mpi().size(), (OpenPGP::PKA::Values::size_type) 1);

    const OpenPGP::Message decrypted = OpenPGP::Decrypt::pka(pri, PASSPHRASE, encrypted);
    std::string message = "";
    for(OpenPGP::Packet::Tag::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == OpenPGP::Packet::LITERAL_DATA){
            message += std::dynamic_pointer_cast <OpenPGP::Packet::Tag11> (p) -> out(false);
        }
    }
    EXPECT_EQ(message, MESSAGE);

    EXPECT_EQ(OpenPGP::Verify::binary(pri, decrypted), true);
}

TEST(PGP, sign_verify_detached){

    OpenPGP::SecretKey pri;
    ASSERT_EQ(read_pgp <OpenPGP::SecretKey> ("Alicepri", pri), true);

    const OpenPGP::Sign::Args sign_args(pri, PASSPHRASE);
    const OpenPGP::DetachedSignature sig = OpenPGP::Sign::detached_signature(sign_args, MESSAGE);
    EXPECT_EQ(OpenPGP::Verify::detached_signature(pri, MESSAGE, sig), true);
}

TEST(PGP, sign_verify_binary){

    OpenPGP::SecretKey pri;
    ASSERT_EQ(read_pgp <OpenPGP::SecretKey> ("Alicepri", pri), true);

    const OpenPGP::Sign::Args sign_args(pri, PASSPHRASE);
    const OpenPGP::Message sig = OpenPGP::Sign::binary(sign_args, "", MESSAGE, OpenPGP::Compression::ID::ZLIB);
    EXPECT_EQ(OpenPGP::Verify::binary(pri, sig), true);
}

TEST(PGP, sign_verify_cleartext){

    OpenPGP::SecretKey pri;
    ASSERT_EQ(read_pgp <OpenPGP::SecretKey> ("Alicepri", pri), true);

    const OpenPGP::Sign::Args sign_args(pri, PASSPHRASE);
    const OpenPGP::CleartextSignature sig = OpenPGP::Sign::cleartext_signature(sign_args, MESSAGE);
    EXPECT_EQ(OpenPGP::Verify::cleartext_signature(pri, sig), true);
}

TEST(PGP, verify_primary_key){

    OpenPGP::PublicKey pub;
    ASSERT_EQ(read_pgp <OpenPGP::PublicKey> ("Alicepub", pub), true);

    OpenPGP::SecretKey pri;
    ASSERT_EQ(read_pgp <OpenPGP::SecretKey> ("Alicepri", pri), true);

    EXPECT_EQ(OpenPGP::Verify::primary_key(pub, pub), true);
    EXPECT_EQ(OpenPGP::Verify::primary_key(pub, pri), true);
    EXPECT_EQ(OpenPGP::Verify::primary_key(pri, pub), true);
    EXPECT_EQ(OpenPGP::Verify::primary_key(pri, pri), true);
}
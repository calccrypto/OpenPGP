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
    std::string error;

    KeyGen config;

    // no starting user ID packet
    EXPECT_EQ(config.valid(error), false);
    error = "";
    config.uids.push_back(KeyGen::UserID());
    EXPECT_EQ(config.valid(error), true);

    // PKA
    config.pka = 255;                           // invalid PKA
    EXPECT_EQ(config.valid(error), false);
    error = "";
    for(std::pair <std::string const, uint8_t> const & pka : PKA::NUMBER){
        config.pka = pka.second;
        EXPECT_EQ(config.valid(error), PKA::can_sign(config.pka));
    }
    config.pka = PKA::RSA_ENCRYPT_OR_SIGN;
    error = "";

    // Sym
    config.sym = 255;                           // invalid Sym
    EXPECT_EQ(config.valid(error), false);
    for(std::pair <std::string const, uint8_t> const & sym : Sym::NUMBER){
        config.sym = sym.second;                // valid Sym
        EXPECT_EQ(config.valid(error), true);
    }
    config.sym = Sym::AES256;
    error = "";

    // Hash
    config.hash = 255;                          // invalid Hash
    EXPECT_EQ(config.valid(error), false);
    for(std::pair <std::string const, uint8_t> const & hash : Hash::NUMBER){
        config.hash = hash.second;              // valid Hash
        EXPECT_EQ(config.valid(error), true);
    }
    config.sym = Hash::SHA256;
    error = "";

    // add subkey
    config.subkeys.push_back(KeyGen::SubkeyGen());
    EXPECT_EQ(config.valid(error), true);
    error = "";

    // subkey PKA
    config.subkeys[0].pka = 255;                // invalid PKA
    EXPECT_EQ(config.valid(error), false);
    for(std::pair <std::string const, uint8_t> const & pka : PKA::NUMBER){
        config.subkeys[0].pka = pka.second;
        EXPECT_EQ(config.valid(error), true);
    }
    config.subkeys[0].pka = PKA::RSA_ENCRYPT_OR_SIGN;
    error = "";

    // subkey Sym
    config.subkeys[0].sym = 255;                // invalid Sym
    EXPECT_EQ(config.valid(error), false);
    for(std::pair <std::string const, uint8_t> const & sym : Sym::NUMBER){
        config.subkeys[0].sym = sym.second;     // valid Sym
        EXPECT_EQ(config.valid(error), true);
    }
    config.subkeys[0].sym = Sym::AES256;
    error = "";

    // subkey S2K Hash
    config.subkeys[0].hash = 255;               // invalid s2k Hash
    EXPECT_EQ(config.valid(error), false);
    for(std::pair <std::string const, uint8_t> const & hash : Hash::NUMBER){
        config.subkeys[0].hash = hash.second;   // valid s2k Hash
        EXPECT_EQ(config.valid(error), true);
    }
    config.subkeys[0].hash = Hash::SHA256;
    error = "";

    // subkey signing Hash
    config.subkeys[0].sig = 255;               // invalid signing Hash
    EXPECT_EQ(config.valid(error), false);
    for(std::pair <std::string const, uint8_t> const & hash : Hash::NUMBER){
        config.subkeys[0].sig = hash.second;   // valid signing Hash
        EXPECT_EQ(config.valid(error), true);
    }
    config.subkeys[0].sig = Hash::SHA256;
    error = "";

    EXPECT_EQ(config.valid(error), true);

    // generate private key
    const PGPSecretKey pri = generate_key(config, error);
    EXPECT_EQ(pri.meaningful(error), true);

    // extract public key from private
    const PGPPublicKey pub = pri.get_public();
    EXPECT_EQ(pub.meaningful(error), true);

    EXPECT_EQ(pri.keyid(), pub.keyid());
    EXPECT_EQ(pri.fingerprint(), pub.fingerprint());
}

TEST(PGP, revoke_key){
    std::string error;

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    const RevArgs revargs(pri, PASSPHRASE, pri);
    const PGPRevocationCertificate rev = revoke_key_cert(revargs, error);
    ASSERT_EQ(rev.meaningful(error), true);

    // make sure that the revocation certificate generated is for this key
    EXPECT_EQ(verify_revoke(pri, rev, error), true);

    // revoke the key and make sure the returned public key is revoked
    const PGPPublicKey revpub = revoke_with_cert(pri, rev, error);
    EXPECT_EQ(revpub.meaningful(error), true);
    error = "";
    EXPECT_EQ(check_revoked(revpub, error), true);
    EXPECT_EQ(error, "Warning: Revocation Signature found on primary key.\n");

    error = "";

    // revoke directly on the key and make sure it is revoked
    const PGPPublicKey dirrevpub = revoke_key(revargs, error);
    EXPECT_EQ(dirrevpub.meaningful(error), true);
    error = "";
    EXPECT_EQ(check_revoked(dirrevpub, error), true);
    EXPECT_EQ(error, "Warning: Revocation Signature found on primary key.\n");
}

TEST(PGP, revoke_subkey){
    std::string error;

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    const RevArgs revargs(pri, PASSPHRASE, pri);
    const PGPRevocationCertificate rev = revoke_subkey_cert(revargs, unhexlify("d27061e1"), error);
    rev.meaningful(error);
    ASSERT_EQ(rev.meaningful(error), true);

    // make sure that the revocation certificate generated is for this key
    EXPECT_EQ(verify_revoke(pri, rev, error), true);

    // revoke the subkey and make sure the returned public key is revoked
    const PGPPublicKey revsub = revoke_with_cert(pri, rev, error);
    EXPECT_EQ(revsub.meaningful(error), true);
    error = "";
    EXPECT_EQ(check_revoked(revsub, error), true);
    EXPECT_EQ(error, "Warning: Revocation Signature found on subkey.\n");

    error = "";

    // revoke directly on the key and make sure it is revoked
    const PGPPublicKey dirrevsub = revoke_subkey(revargs, unhexlify("d27061e1"), error);
    EXPECT_EQ(dirrevsub.meaningful(error), true);
    error = "";
    EXPECT_EQ(check_revoked(dirrevsub, error), true);
    EXPECT_EQ(error, "Warning: Revocation Signature found on subkey.\n");
}

TEST(PGP, revoke_uid){
    std::string error;

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    const RevArgs revargs(pri, PASSPHRASE, pri);
    const PGPRevocationCertificate rev = revoke_uid_cert(revargs, "alice", error);
    ASSERT_EQ(rev.meaningful(error), true);

    // make sure that the revocation certificate generated is for this key
    EXPECT_EQ(verify_revoke(pri, rev, error), true);

    // revoke the uid and make sure the returned public key is revoked
    const PGPPublicKey revuid = revoke_with_cert(pri, rev, error);
    EXPECT_EQ(revuid.meaningful(error), true);
    error = "";
    EXPECT_EQ(check_revoked(revuid, error), true);
    EXPECT_EQ(error, "Warning: Revocation Signature found on UID.\n");

    error = "";

    // revoke directly on the key and make sure it is revoked
    const PGPPublicKey dirrevuid = revoke_uid(revargs, "alice", error);
    EXPECT_EQ(dirrevuid.meaningful(error), true);
    error = "";
    EXPECT_EQ(check_revoked(dirrevuid, error), true);
    EXPECT_EQ(error, "Warning: Revocation Signature found on UID.\n");
}

TEST(PGP, encrypt_decrypt_pka_mdc){
    std::string error;

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    const EncryptArgs encrypt_args("", MESSAGE);
    const PGPMessage encrypted = encrypt_pka(encrypt_args, pri, error);
    EXPECT_EQ(encrypted.meaningful(error), true);

    const PGP::Packets packets = encrypted.get_packets();
    EXPECT_EQ(packets[0] -> get_tag(), Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY);
    EXPECT_EQ(packets[1] -> get_tag(), Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA);

    const Tag1::Ptr tag1  = std::dynamic_pointer_cast <Tag1> (packets[0]);
    EXPECT_EQ(tag1 -> get_version(), (uint8_t) 3);
    EXPECT_EQ(tag1 -> get_keyid(), pri.keyid());
    EXPECT_EQ(tag1 -> get_pka(), PKA::RSA_ENCRYPT_OR_SIGN);
    EXPECT_EQ(tag1 -> get_mpi().size(), (PKA::Values::size_type) 1);

    const PGPMessage decrypted = decrypt_pka(pri, PASSPHRASE, encrypted, error);
    std::string message = "";
    for(Packet::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == Packet::LITERAL_DATA){
            message += std::dynamic_pointer_cast <Tag11> (p) -> out(false);
        }
    }
    EXPECT_EQ(message, MESSAGE);
}

TEST(PGP, encrypt_decrypt_pka_no_mdc){
    std::string error;

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    EncryptArgs encrypt_args;
    encrypt_args.data = MESSAGE;
    encrypt_args.mdc = false;

    const PGPMessage encrypted = encrypt_pka(encrypt_args, pri, error);
    EXPECT_EQ(encrypted.meaningful(error), true);

    const PGP::Packets packets = encrypted.get_packets();
    EXPECT_EQ(packets[0] -> get_tag(), Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY);
    EXPECT_EQ(packets[1] -> get_tag(), Packet::SYMMETRICALLY_ENCRYPTED_DATA);

    Tag1::Ptr tag1 = std::dynamic_pointer_cast <Tag1> (packets[0]);
    EXPECT_EQ(tag1 -> get_version(), (uint8_t) 3);
    EXPECT_EQ(tag1 -> get_keyid(), pri.keyid());
    EXPECT_EQ(tag1 -> get_pka(), PKA::RSA_ENCRYPT_OR_SIGN);
    EXPECT_EQ(tag1 -> get_mpi().size(), (PKA::Values::size_type) 1);

    const PGPMessage decrypted = decrypt_pka(pri, PASSPHRASE, encrypted, error);
    std::string message = "";
    for(Packet::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == Packet::LITERAL_DATA){
            message += std::dynamic_pointer_cast <Tag11> (p) -> out(false);
        }
    }
    EXPECT_EQ(message, MESSAGE);
}

TEST(PGP, encrypt_decrypt_symmetric_mdc){
    std::string error;

    const EncryptArgs encrypt_args("", MESSAGE);
    const PGPMessage encrypted = encrypt_sym(encrypt_args, PASSPHRASE, Sym::AES256, error);
    EXPECT_EQ(encrypted.meaningful(error), true);

    const PGP::Packets packets = encrypted.get_packets();
    EXPECT_EQ(packets[0] -> get_tag(), Packet::SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY);
    EXPECT_EQ(packets[1] -> get_tag(), Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA);

    const Tag3::Ptr tag3  = std::dynamic_pointer_cast <Tag3>  (packets[0]);
    EXPECT_EQ(tag3 -> get_version(), (uint8_t) 4);

    const PGPMessage decrypted = decrypt_sym(encrypted, PASSPHRASE, error);
    std::string message = "";
    for(Packet::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == Packet::LITERAL_DATA){
            message += std::dynamic_pointer_cast <Tag11> (p) -> out(false);
        }
    }
    EXPECT_EQ(message, MESSAGE);
}

TEST(PGP, encrypt_decrypt_symmetric_no_mdc){
    std::string error;

    EncryptArgs encrypt_args;
    encrypt_args.data = MESSAGE;
    encrypt_args.mdc = false;

    const PGPMessage encrypted = encrypt_sym(encrypt_args, PASSPHRASE, Sym::AES256, error);
    EXPECT_EQ(encrypted.meaningful(error), true);

    const PGP::Packets packets = encrypted.get_packets();
    EXPECT_EQ(packets[0] -> get_tag(), Packet::SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY);
    EXPECT_EQ(packets[1] -> get_tag(), Packet::SYMMETRICALLY_ENCRYPTED_DATA);

    const Tag3::Ptr tag3 = std::dynamic_pointer_cast <Tag3> (packets[0]);
    EXPECT_EQ(tag3 -> get_version(), (uint8_t) 4);

    const PGPMessage decrypted = decrypt_sym(encrypted, PASSPHRASE, error);
    std::string message = "";
    for(Packet::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == Packet::LITERAL_DATA){
            message += std::dynamic_pointer_cast <Tag11> (p) -> out(false);
        }
    }
    EXPECT_EQ(message, MESSAGE);
}

TEST(PGP, encrypt_sign_decrypt_verify){
    std::string error;

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    EncryptArgs encrypt_args;
    encrypt_args.data = MESSAGE;
    encrypt_args.signer = std::make_shared <PGPSecretKey> (pri);
    encrypt_args.passphrase = PASSPHRASE;

    const PGPMessage encrypted = encrypt_pka(encrypt_args, pri, error);
    EXPECT_EQ(encrypted.meaningful(error), true);

    const PGP::Packets packets = encrypted.get_packets();
    EXPECT_EQ(packets[0] -> get_tag(), Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY);
    EXPECT_EQ(packets[1] -> get_tag(), Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA);

    const Tag1::Ptr tag1  = std::dynamic_pointer_cast <Tag1> (packets[0]);
    EXPECT_EQ(tag1 -> get_version(), (uint8_t) 3);
    EXPECT_EQ(tag1 -> get_keyid(), pri.keyid());
    EXPECT_EQ(tag1 -> get_pka(), PKA::RSA_ENCRYPT_OR_SIGN);
    EXPECT_EQ(tag1 -> get_mpi().size(), (PKA::Values::size_type) 1);

    const PGPMessage decrypted = decrypt_pka(pri, PASSPHRASE, encrypted, error);
    std::string message = "";
    for(Packet::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == Packet::LITERAL_DATA){
            message += std::dynamic_pointer_cast <Tag11> (p) -> out(false);
        }
    }
    EXPECT_EQ(message, MESSAGE);

    EXPECT_EQ(verify_binary(pri, decrypted, error), true);
}

TEST(PGP, sign_verify_detached){
    std::string error;

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    const SignArgs sign_args(pri, PASSPHRASE);
    const PGPDetachedSignature sig = sign_detached_signature(sign_args, MESSAGE, error);
    EXPECT_EQ(verify_detached_signature(pri, MESSAGE, sig, error), true);
}

TEST(PGP, sign_verify_binary){
    std::string error;

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    const SignArgs sign_args(pri, PASSPHRASE);
    const PGPMessage sig = sign_binary(sign_args, "", MESSAGE, Compression::ZLIB, error);
    EXPECT_EQ(verify_binary(pri, sig, error), true);
}

TEST(PGP, sign_verify_cleartext){
    std::string error;

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    const SignArgs sign_args(pri, PASSPHRASE);
    const PGPCleartextSignature sig = sign_cleartext_signature(sign_args, MESSAGE, error);
    EXPECT_EQ(verify_cleartext_signature(pri, sig, error), true);
}

TEST(PGP, verify_primary_key){
    std::string error;

    PGPPublicKey pub;
    ASSERT_EQ(read_pgp <PGPPublicKey> ("Alicepub", pub), true);

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    EXPECT_EQ(verify_primary_key(pub, pub, error), true);
    EXPECT_EQ(verify_primary_key(pub, pri, error), true);
    EXPECT_EQ(verify_primary_key(pri, pub, error), true);
    EXPECT_EQ(verify_primary_key(pri, pri, error), true);
}
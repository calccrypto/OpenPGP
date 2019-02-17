#include <cstdlib>
#include <ctime>
#include <sstream>

#include <gtest/gtest.h>

#include "arm_key.h"
#include "decrypt.h"
#include "encrypt.h"
#include "keygen.h"
#include "revoke.h"
#include "sign.h"
#include "verify.h"

#include "testvectors/msg.h"
#include "testvectors/pass.h"
#include "testvectors/read_pgp.h"

TEST(PGP, keygen){

    OpenPGP::KeyGen::Config config;

    // no starting user ID packet
    EXPECT_EQ(config.valid(), false);
    config.uids.push_back(OpenPGP::KeyGen::Config::UserID());
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
        // ECDH cannot sign
        if (pka.second == OpenPGP::PKA::ID::ECDH){
            continue;
        }
        if (pka.second == OpenPGP::PKA::ID::ECDSA || pka.second == OpenPGP::PKA::ID::EdDSA){
            config.bits = 1024;
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
    config.subkeys.push_back(OpenPGP::KeyGen::Config::SubkeyGen());
    EXPECT_EQ(config.valid(), true);

    // subkey PKA
    config.subkeys[0].pka = 255;                // invalid PKA
    EXPECT_EQ(config.valid(), false);
    for(std::pair <std::string const, uint8_t> const & pka : OpenPGP::PKA::NUMBER){
        #ifdef GPG_COMPATIBLE
        if (pka.second == OpenPGP::PKA::ID::ECDSA || pka.second == OpenPGP::PKA::ID::EdDSA || pka.second == OpenPGP::PKA::ID::ECDH){
            config.subkeys[0].bits = 1024;
        }
        #endif
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
    const OpenPGP::SecretKey pri = OpenPGP::KeyGen::generate_key(config);
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

TEST(Key, get_pkey){
    OpenPGP::Key::Ptr k (new OpenPGP::Key(arm));
    OpenPGP::Key::pkey pk = k->get_pkey();
    for (OpenPGP::Key::SigPairs::iterator it = pk.keySigs.begin(); it != pk.keySigs.end(); it++){
        ASSERT_TRUE(it->first == pk.key); // The keySigs multimap must contain only the primary key (with its signatures)
    }
    // All the packets must be in the pkey struct
    for (const OpenPGP::Packet::Tag::Ptr &p: k->get_packets()){
        bool found = false;
        if (p == pk.key){
            found = true;
        }
        else{
            for (OpenPGP::Key::SigPairs::iterator it = pk.keySigs.begin(); it != pk.keySigs.end(); it++){
                if (p == it->first || p == it->second){
                    found = true;
                    continue;
                }
            }
            for (OpenPGP::Key::SigPairs::iterator it = pk.uids.begin(); it != pk.uids.end(); it++){
                if (p == it->first || p == it->second){
                    found = true;
                    continue;
                }
            }
            for (OpenPGP::Key::SigPairs::iterator it = pk.subKeys.begin(); it != pk.subKeys.end(); it++){
                if (p == it->first || p == it->second){
                    found = true;
                    continue;
                }
            }
        }
        ASSERT_TRUE(found);
    }
    // All the packet in the struct pkey must be in the key packets list
    ASSERT_TRUE(std::find(k->get_packets().begin(), k->get_packets().end(), pk.key) != k->get_packets().end());
    for (OpenPGP::Key::SigPairs::iterator it = pk.keySigs.begin(); it != pk.keySigs.end(); it++){
        ASSERT_TRUE(std::find(k->get_packets().begin(), k->get_packets().end(), it->first) != k->get_packets().end());
        ASSERT_TRUE(std::find(k->get_packets().begin(), k->get_packets().end(), it->second) != k->get_packets().end());
    }
    for (OpenPGP::Key::SigPairs::iterator it = pk.uids.begin(); it != pk.uids.end(); it++){
        ASSERT_TRUE(std::find(k->get_packets().begin(), k->get_packets().end(), it->first) != k->get_packets().end());
        ASSERT_TRUE(std::find(k->get_packets().begin(), k->get_packets().end(), it->second) != k->get_packets().end());
    }
    for (OpenPGP::Key::SigPairs::iterator it = pk.subKeys.begin(); it != pk.subKeys.end(); it++){
        ASSERT_TRUE(std::find(k->get_packets().begin(), k->get_packets().end(), it->first) != k->get_packets().end());
        ASSERT_TRUE(std::find(k->get_packets().begin(), k->get_packets().end(), it->second) != k->get_packets().end());
    }
}

OpenPGP::Key::Packets create_partial_packets(OpenPGP::Key::Packets ps){
    OpenPGP::Key::Packets partial_ps;
    unsigned int i = 0;

    partial_ps.push_back(ps[i]);
    i++;
    while (i < ps.size()){
        while(i < ps.size() && ps[i]->get_tag() == OpenPGP::Packet::SIGNATURE){
            if (rand() % 2){
                partial_ps.push_back(ps[i]);
            }
            i++;
        }
        while(i < ps.size() && ps[i]->get_tag() == OpenPGP::Packet::USER_ID){
            if (rand() % 2){
                partial_ps.push_back(ps[i]);
                i++;
                while(i < ps.size() && ps[i]->get_tag() == OpenPGP::Packet::SIGNATURE){
                    if (rand() % 2){
                        partial_ps.push_back(ps[i]);
                    }
                    i++;
                }
                while(i < ps.size() && ps[i]->get_tag() == OpenPGP::Packet::USER_ATTRIBUTE){
                    if (rand() % 2){
                        partial_ps.push_back(ps[i]);
                        i++;
                        while(i < ps.size() && ps[i]->get_tag()== OpenPGP::Packet::SIGNATURE){
                            if (rand() % 2){
                                partial_ps.push_back(ps[i]);
                            }
                            i++;
                        }
                    }
                    else{
                        i++;
                        while(i < ps.size() && ps[i]->get_tag()== OpenPGP::Packet::SIGNATURE){i++;}
                    }
                }
            }
            else{
                i++;
                while(i < ps.size() && ps[i]->get_tag()!= OpenPGP::Packet::USER_ID){i++;}
            }
        }
        while(i < ps.size() && ps[i]->get_tag() == OpenPGP::Packet::PUBLIC_SUBKEY){
            if (rand() % 2){
                partial_ps.push_back(ps[i]);
                i++;
                while(i < ps.size() && ps[i]->get_tag() == OpenPGP::Packet::SIGNATURE){
                    if (rand() % 2){
                        partial_ps.push_back(ps[i]);
                    }
                    i++;
                }
            }
            else{
                i++;
                while(i < ps.size() && ps[i]->get_tag()== OpenPGP::Packet::SIGNATURE){i++;}
            }
        }
    }
    return partial_ps;
}

OpenPGP::Packet::Tag::Ptr find_key_from_obj(OpenPGP::Key::SigPairs sp, OpenPGP::Packet::Tag::Ptr p){
    for (OpenPGP::Key::SigPairs::iterator it = sp.begin(); it != sp.end(); it++){
        if (it->second == p){
            return it->first;
        }
    }
    return nullptr;
}

TEST(Key, merge){
    srand(time(0));
    OpenPGP::Key::Ptr main_key (new OpenPGP::Key(arm));
    OpenPGP::Key::Ptr partial_key_1 (new OpenPGP::Key(arm));
    OpenPGP::Key::Ptr partial_key_2 (new OpenPGP::Key(arm));
    do{
        partial_key_1 ->
        set_packets_clone(create_partial_packets(main_key->get_packets()));
    }while(!partial_key_1 -> meaningful());
    do{
        partial_key_2 ->
        set_packets_clone(create_partial_packets(main_key->get_packets()));
    }while(!partial_key_2 -> meaningful());

    OpenPGP::Key::pkey pk_1 = partial_key_1->get_pkey();
    OpenPGP::Key::pkey pk_2 = partial_key_2->get_pkey();
    partial_key_1 -> merge(partial_key_2);

    // The merged the must be meaningful
    ASSERT_TRUE(partial_key_1->meaningful());

    // Each packet in pkey must be in the new packets list
    OpenPGP::Key::Packets ps = partial_key_1->get_packets();
    std::find(ps.begin(), ps.end(), pk_1.key);
    for(OpenPGP::Key::SigPairs::iterator it = pk_1.keySigs.begin(); it != pk_1.keySigs.end(); it++){
        ASSERT_TRUE(std::find(ps.begin(), ps.end(), it->first) != ps.end());
        ASSERT_TRUE(std::find(ps.begin(), ps.end(), it->second) != ps.end());
    }
    for(OpenPGP::Key::SigPairs::iterator it = pk_1.uids.begin(); it != pk_1.uids.end(); it++){
        ASSERT_TRUE(std::find(ps.begin(), ps.end(), it->first) != ps.end());
        ASSERT_TRUE(std::find(ps.begin(), ps.end(), it->second) != ps.end());
    }
    for(OpenPGP::Key::SigPairs::iterator it = pk_1.subKeys.begin(); it != pk_1.subKeys.end(); it++){
        ASSERT_TRUE(std::find(ps.begin(), ps.end(), it->first) != ps.end());
        ASSERT_TRUE(std::find(ps.begin(), ps.end(), it->second) != ps.end());
    }

    // Same for pkey_2
    for(OpenPGP::Key::SigPairs::iterator it = pk_2.keySigs.begin(); it != pk_2.keySigs.end(); it++){
        ASSERT_TRUE(std::find(ps.begin(), ps.end(), it->first) != ps.end());
        ASSERT_TRUE(std::find(ps.begin(), ps.end(), it->second) != ps.end());
    }
    for(OpenPGP::Key::SigPairs::iterator it = pk_2.uids.begin(); it != pk_2.uids.end(); it++){
        ASSERT_TRUE(std::find(ps.begin(), ps.end(), it->first) != ps.end());
        ASSERT_TRUE(std::find(ps.begin(), ps.end(), it->second) != ps.end());
    }
    for(OpenPGP::Key::SigPairs::iterator it = pk_2.subKeys.begin(); it != pk_2.subKeys.end(); it++){
        ASSERT_TRUE(std::find(ps.begin(), ps.end(), it->first) != ps.end());
        ASSERT_TRUE(std::find(ps.begin(), ps.end(), it->second) != ps.end());
    }

    // Each packet in the new key must be in the correct position
    OpenPGP::Packet::Tag::Ptr last_pri_packet = ps[0];
    for (const OpenPGP::Packet::Tag::Ptr &p: ps){
        switch (p->get_tag()){
            case OpenPGP::Packet::PUBLIC_KEY:
            case OpenPGP::Packet::SECRET_KEY:
            case OpenPGP::Packet::USER_ID:
            case OpenPGP::Packet::USER_ATTRIBUTE:
            case OpenPGP::Packet::PUBLIC_SUBKEY:
            case OpenPGP::Packet::SECRET_SUBKEY:
                last_pri_packet = p;
                break;
            case OpenPGP::Packet::SIGNATURE:
                switch (last_pri_packet->get_tag()){
                    case OpenPGP::Packet::PUBLIC_KEY:
                    case OpenPGP::Packet::SECRET_KEY: {
                        OpenPGP::Packet::Tag::Ptr mm_key_1 = find_key_from_obj(pk_1.keySigs, p);
                        OpenPGP::Packet::Tag::Ptr mm_key_2 = find_key_from_obj(pk_2.keySigs, p);
                        bool cond_1 = false;
                        bool cond_2 = false;
                        if (mm_key_1){
                            cond_1 = mm_key_1 == last_pri_packet;
                        }
                        if (mm_key_2){
                            cond_2 = mm_key_2 == last_pri_packet;
                        }
                        ASSERT_TRUE(cond_1 || cond_2);
                        break;
                    }
                    case OpenPGP::Packet::USER_ID:
                    case OpenPGP::Packet::USER_ATTRIBUTE: {
                        OpenPGP::Packet::Tag::Ptr mm_key_1 = find_key_from_obj(pk_1.uids, p);
                        OpenPGP::Packet::Tag::Ptr mm_key_2 = find_key_from_obj(pk_2.uids, p);
                        bool cond_1 = false;
                        bool cond_2 = false;
                        if (mm_key_1){
                            cond_1 = mm_key_1 == last_pri_packet;
                        }
                        if (mm_key_2){
                            cond_2 = mm_key_2 == last_pri_packet;
                        }
                        ASSERT_TRUE(cond_1 || cond_2);
                        break;
                    }
                    case OpenPGP::Packet::PUBLIC_SUBKEY:
                    case OpenPGP::Packet::SECRET_SUBKEY: {
                        OpenPGP::Packet::Tag::Ptr mm_key_1 = find_key_from_obj(pk_1.subKeys, p);
                        OpenPGP::Packet::Tag::Ptr mm_key_2 = find_key_from_obj(pk_2.subKeys, p);
                        bool cond_1 = false;
                        bool cond_2 = false;
                        if (mm_key_1){
                            cond_1 = mm_key_1 == last_pri_packet;
                        }
                        if (mm_key_2){
                            cond_2 = mm_key_2 == last_pri_packet;
                        }
                        ASSERT_TRUE(cond_1 || cond_2);
                        break;
                    }
                    default:
                        ASSERT_TRUE(false); // This should never happen
                        break;
                }
                break;
            default:
                ASSERT_TRUE(false); // This should never happen
                break;
        }

    }
}

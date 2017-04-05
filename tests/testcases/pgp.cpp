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

#include "testvectors/msgpass.h"
#include "testvectors/gpg/pgpprikey.h"
#include "testvectors/gpg/pgppubkey.h"
#include "testvectors/gpg/pgprevoke.h"
#include "testvectors/gpg/pgpsign.h"

time_t get_utc(int year, int month, int day, int hour, int minute, int second){
    tm in;
    in.tm_year = year - 1900;
    in.tm_mon  = month - 1;
    in.tm_mday = day;
    in.tm_hour = hour;
    in.tm_min  = minute;
    in.tm_sec  = second;
    time_t result = mktime(&in); // generate by local timezone

    // detect timezone
    int utc = 0, local = 0;
    tm *tmp;
    tmp = gmtime(&result);
    utc = tmp -> tm_hour;
    tmp = localtime(&result);
    local = tmp -> tm_hour;
    if ( utc != local ){
        int diff = local - utc;
        if ( diff < 0 && diff < -12 ){
            diff += 24;
        } else if (diff > 0 && diff > 12){
            diff -= 24;
        }
        result += diff*60*60;
    }
    return result;
}

TEST(PGP, keygen_config){
    std::string error;
    KeyGen config;

    // no starting user ID packet
    EXPECT_EQ(config.valid(error), false);
    config.uids.push_back(KeyGen::UserID());
    EXPECT_EQ(config.valid(error), true);

    // PKA
    config.pka = 255;                           // invalid PKA
    EXPECT_EQ(config.valid(error), false);
    for(std::pair <std::string const, uint8_t> const & pka : PKA::NUMBER){
        config.pka = pka.second;
        EXPECT_EQ(config.valid(error), PKA::can_sign(config.pka));
    }
    config.pka = PKA::RSA_ENCRYPT_OR_SIGN;

    // Sym
    config.sym = 255;                           // invalid Sym
    EXPECT_EQ(config.valid(error), false);
    for(std::pair <std::string const, uint8_t> const & sym : Sym::NUMBER){
        config.sym = sym.second;                // valid Sym
        EXPECT_EQ(config.valid(error), true);
    }
    config.sym = Sym::AES256;

    // Hash
    config.hash = 255;                          // invalid Hash
    EXPECT_EQ(config.valid(error), false);
    for(std::pair <std::string const, uint8_t> const & hash : Hash::NUMBER){
        config.hash = hash.second;              // valid Hash
        EXPECT_EQ(config.valid(error), true);
    }
    config.sym = Hash::SHA256;

    // add subkey
    config.subkeys.push_back(KeyGen::SubkeyGen());
    EXPECT_EQ(config.valid(error), true);

    // subkey PKA
    config.subkeys[0].pka = 255;                // invalid PKA
    EXPECT_EQ(config.valid(error), false);
    for(std::pair <std::string const, uint8_t> const & pka : PKA::NUMBER){
        config.subkeys[0].pka = pka.second;
        EXPECT_EQ(config.valid(error), true);
    }
    config.subkeys[0].pka = PKA::RSA_ENCRYPT_OR_SIGN;

    // subkey Sym
    config.subkeys[0].sym = 255;                // invalid Sym
    EXPECT_EQ(config.valid(error), false);
    for(std::pair <std::string const, uint8_t> const & sym : Sym::NUMBER){
        config.subkeys[0].sym = sym.second;     // valid Sym
        EXPECT_EQ(config.valid(error), true);
    }
    config.subkeys[0].sym = Sym::AES256;

    // subkey S2K Hash
    config.subkeys[0].hash = 255;               // invalid s2k Hash
    EXPECT_EQ(config.valid(error), false);
    for(std::pair <std::string const, uint8_t> const & hash : Hash::NUMBER){
        config.subkeys[0].hash = hash.second;   // valid s2k Hash
        EXPECT_EQ(config.valid(error), true);
    }
    config.subkeys[0].hash = Hash::SHA256;

    // subkey signing Hash
    config.subkeys[0].sig = 255;               // invalid signing Hash
    EXPECT_EQ(config.valid(error), false);
    for(std::pair <std::string const, uint8_t> const & hash : Hash::NUMBER){
        config.subkeys[0].sig = hash.second;   // valid signing Hash
        EXPECT_EQ(config.valid(error), true);
    }
    config.subkeys[0].sig = Hash::SHA256;

    EXPECT_EQ(config.valid(error), true);
}

TEST(PGP, keygen){
    std::string error;
    KeyGen config;

    // no starting user ID packet
    EXPECT_EQ(config.valid(error), false);
    config.uids.push_back(KeyGen::UserID());
    EXPECT_EQ(config.valid(error), true);

    // add subkey
    config.subkeys.push_back(KeyGen::SubkeyGen());

    // generate private key
    const PGPSecretKey pri = generate_key(config, error);
    EXPECT_EQ(pri.meaningful(error), true);

    // extract public key from private
    const PGPPublicKey pub = pri.get_public();
    EXPECT_EQ(pub.meaningful(error), true);
}

TEST(PGP, public_key){
    PGPPublicKey pgp(GPG_PUBKEY_ALICE);

    auto packets = pgp.get_packets();
    ASSERT_EQ(packets.size(), (PGP::Packets::size_type) 5);

    Packet::Ptr
            p0 = packets[0],
            p1 = packets[1],
            p2 = packets[2],
            p3 = packets[3],
            p4 = packets[4];

    ASSERT_EQ(p0 -> get_tag(), Packet::PUBLIC_KEY);
    ASSERT_EQ(p1 -> get_tag(), Packet::USER_ID);
    ASSERT_EQ(p2 -> get_tag(), Packet::SIGNATURE);
    ASSERT_EQ(p3 -> get_tag(), Packet::PUBLIC_SUBKEY);
    ASSERT_EQ(p4 -> get_tag(), Packet::SIGNATURE);
    Tag6::Ptr  pubkey = std::dynamic_pointer_cast <Tag6>  (p0);
    Tag13::Ptr userid = std::dynamic_pointer_cast <Tag13> (p1);
    Tag14::Ptr subkey = std::dynamic_pointer_cast <Tag14> (p3);
    Tag2::Ptr  pubsig = std::dynamic_pointer_cast <Tag2>  (p2),
               subsig = std::dynamic_pointer_cast <Tag2>  (p4);

    EXPECT_EQ(pubkey -> get_version(), (uint8_t) 4);
    EXPECT_EQ(subkey -> get_version(), (uint8_t) 4);
    EXPECT_EQ(pubsig -> get_version(), (uint8_t) 4);
    EXPECT_EQ(subsig -> get_version(), (uint8_t) 4);
    EXPECT_EQ(userid -> get_version(), (uint8_t) 0);    // undefined

    EXPECT_EQ(pubkey -> get_size(), (std::size_t) 269);
    EXPECT_EQ(userid -> get_size(), (std::size_t) 36);
    EXPECT_EQ(pubsig -> get_size(), (std::size_t) 312);
    EXPECT_EQ(subkey -> get_size(), (std::size_t) 269);
    EXPECT_EQ(subsig -> get_size(), (std::size_t) 287);

    time_t gen_time = get_utc(2014, 6, 22, 12, 50, 48);

    // pubkey
    {
        EXPECT_EQ(pubkey -> get_time(), gen_time);      // 2014-06-22T12:50:48 UTC
        EXPECT_EQ(pubkey -> get_pka(), PKA::RSA_ENCRYPT_OR_SIGN);
        auto mpi = pubkey -> get_mpi();
        auto n = mpi[0], e = mpi[1];
        EXPECT_EQ(bitsize(n), (std::size_t) 2048);      // 2048-bit
        EXPECT_EQ(mpitohex(n), "bc047e94d471f3ccbd525d6a6f8e17f7b1f00527c722c3913ce787fbd0090e3af8be7e59410f63b3983a9507b761045c11510e62f5a8cfbcdc180976a4c225737b8e06d8531f38c6eaa996954d5521a6763231f07c2b43605d052abdf39d6c668ac94bc89f543052d050530c70c48a49a970867c00178f9076dd0e151d254632767b2926e9baa22c6d0c213f1f45de74991396d7e8d10508cf679139410ab311b1279dd3c0d37facca54d523cd14a3df488eb8f592c5a19bcfede67c8170815c588adf39d188197da40492aac5b183c303f6ef23b0b5e48ff73b2d806afb0fb4f16ba32769249d3a7ca0ef0b9b3d57852dc9a979b6d56f3dc170e28dcb2e536d");
        EXPECT_EQ(bitsize(e), (std::size_t) 17);        // 17-bit
        EXPECT_EQ(e, 0x10001);
    }

    // userid
    {
        EXPECT_EQ(userid -> raw(), "alice (test key) <alice@example.com>");
    }

    // pubsig
    {
        EXPECT_EQ(pubsig -> get_type(), Signature_Type::POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET);
        EXPECT_EQ(pubsig -> get_pka(), PKA::RSA_ENCRYPT_OR_SIGN);
        EXPECT_EQ(pubsig -> get_hash(), Hash::SHA1);
        EXPECT_EQ(pubsig -> get_left16(), "\x04\x5e");
        auto mpi = pubsig -> get_mpi();
        ASSERT_EQ(mpi.size(), (PKA::Values::size_type) 1);
        EXPECT_EQ(bitsize(mpi[0]), (std::size_t) 2047); // 2047-bit
        EXPECT_EQ(mpitohex(mpi[0]), "688a18a258f866cf50f1c938dc15b11298da0bfbd680241f52545af5023722858cdfb579da22e66dae36dff9a817f797192e95b7074bab49381acb837f1216d4e8e3c2de2fb5547a515b5236823bcb4b3bca1a68455fa984c4dc21b1a5af2308aea580c0ae2ca3f5db343beaa559524702d09e40d1923314ef0f15646acec91b9c6d9cba9d9b87fa78626a522ae1520f0aed361df00f8191a9ecb1fb12732e9f6e5e1c4bece397e4dcfbacd41918882c2dfa75b98b54587f0cd61195bdce41b690329a746c6e37b7e2ef9b06206bf280ff93ec0b891929790492a9971acaa9e7e141585ca41800dd462b6f8235c0f1e0b691a5054da8f90295f5949e22fb5e5c");
        // pubsig/hashed
        auto pubsub = pubsig -> get_hashed_subpackets();
        ASSERT_EQ(pubsub.size(), (Tag2::Subpackets::size_type) 7);
        Subpacket::Ptr
                ps0 = pubsub[0],
                ps1 = pubsub[1],
                ps2 = pubsub[2],
                ps3 = pubsub[3],
                ps4 = pubsub[4],
                ps5 = pubsub[5],
                ps6 = pubsub[6];

        ASSERT_EQ(ps0 -> get_type(), Tag2Subpacket::SIGNATURE_CREATION_TIME);
        ASSERT_EQ(ps1 -> get_type(), Tag2Subpacket::KEY_FLAGS);
        ASSERT_EQ(ps2 -> get_type(), Tag2Subpacket::PREFERRED_SYMMETRIC_ALGORITHMS);
        ASSERT_EQ(ps3 -> get_type(), Tag2Subpacket::PREFERRED_HASH_ALGORITHMS);
        ASSERT_EQ(ps4 -> get_type(), Tag2Subpacket::PREFERRED_COMPRESSION_ALGORITHMS);
        ASSERT_EQ(ps5 -> get_type(), Tag2Subpacket::FEATURES);
        ASSERT_EQ(ps6 -> get_type(), Tag2Subpacket::KEY_SERVER_PREFERENCES);
        Tag2Sub2::Ptr  pubsub2  = std::dynamic_pointer_cast <Tag2Sub2>  (ps0);
        Tag2Sub27::Ptr pubsub27 = std::dynamic_pointer_cast <Tag2Sub27> (ps1);
        Tag2Sub11::Ptr pubsub11 = std::dynamic_pointer_cast <Tag2Sub11> (ps2);
        Tag2Sub21::Ptr pubsub21 = std::dynamic_pointer_cast <Tag2Sub21> (ps3);
        Tag2Sub22::Ptr pubsub22 = std::dynamic_pointer_cast <Tag2Sub22> (ps4);
        Tag2Sub30::Ptr pubsub30 = std::dynamic_pointer_cast <Tag2Sub30> (ps5);
        Tag2Sub23::Ptr pubsub23 = std::dynamic_pointer_cast <Tag2Sub23> (ps6);

        // pubsig/sub2
        {
            EXPECT_EQ(pubsub2 -> get_time(), gen_time); // 2014-06-22T12:50:48 UTC
        }
        // pubsig/sub27
        {
            EXPECT_EQ(pubsub27 -> get_flags(), std::string(1, 1 | 2));
        }
        // pubsig/sub11
        {
            std::string psa = pubsub11 -> get_psa();
            EXPECT_EQ(psa.size(), (std::string::size_type) 5);
            EXPECT_NE(psa.find(Sym::AES256),    std::string::npos);
            EXPECT_NE(psa.find(Sym::AES192),    std::string::npos);
            EXPECT_NE(psa.find(Sym::AES128),    std::string::npos);
            EXPECT_NE(psa.find(Sym::CAST5),     std::string::npos);
            EXPECT_NE(psa.find(Sym::TRIPLEDES), std::string::npos);
        }
        // pubsig/sub21
        {
            std::string pha = pubsub21 -> get_pha();
            EXPECT_EQ(pha.size(), (std::string::size_type) 5);
            EXPECT_NE(pha.find(Hash::SHA256), std::string::npos);
            EXPECT_NE(pha.find(Hash::SHA1),   std::string::npos);
            EXPECT_NE(pha.find(Hash::SHA384), std::string::npos);
            EXPECT_NE(pha.find(Hash::SHA512), std::string::npos);
            EXPECT_NE(pha.find(Hash::SHA224), std::string::npos);
        }
        // pubsig/sub22
        {
            std::string pca = pubsub22 -> get_pca();
            EXPECT_EQ(pca.size(), (std::string::size_type) 3);
            EXPECT_NE(pca.find(Compression::ZLIB),  std::string::npos);
            EXPECT_NE(pca.find(Compression::BZIP2), std::string::npos);
            EXPECT_NE(pca.find(Compression::ZIP),   std::string::npos);
        }
        // pubsig/sub30
        {
            EXPECT_EQ(pubsub30 -> get_flags().size(), (std::string::size_type) 1);
            EXPECT_EQ(pubsub30 -> get_flags()[0], Features_Flags::MODIFICATION_DETECTION);
        }
        // pubsig/sub23
        {
            EXPECT_EQ(pubsub23 -> get_flags().size(), (std::string::size_type) 1);
            EXPECT_EQ(static_cast <uint8_t> (pubsub23 -> get_flags()[0]), Key_Server_Preferences::NO_MODIFY);
        }

        // pubsig/unhashed
        auto uh_pubsub = pubsig -> get_unhashed_subpackets();
        ASSERT_EQ(uh_pubsub.size(), (Tag2::Subpackets::size_type) 1);
        Subpacket::Ptr uhps0 = uh_pubsub[0];
        ASSERT_EQ(uhps0 -> get_type(), Tag2Subpacket::ISSUER);
        Tag2Sub16::Ptr pubsub16 = std::dynamic_pointer_cast <Tag2Sub16> (uhps0);
        // pubsig/sub16
        {
            EXPECT_EQ(pubsub16 -> get_keyid(), "\xd5\xd7\xda\x71\xc3\x54\x96\x0e");
        }
    }

    // subkey
    {
        EXPECT_EQ(subkey -> get_time(), gen_time);                     // 2014-06-22T12:50:48 UTC
        EXPECT_EQ(subkey -> get_pka(), PKA::RSA_ENCRYPT_OR_SIGN);
        auto mpi = subkey -> get_mpi();
        auto n = mpi[0], e = mpi[1];
        EXPECT_EQ(bitsize(n), (std::size_t) 2048);                     // 2048-bit
        EXPECT_EQ(mpitohex(n), "d98aac4e3f499e2264aebd71ea0e7d8a8d4690ff73d09125cd197892f1bb59492b8523dc5e4a0b9e0702babf65a71113d96a7ba2ee37cdc2ae8b0b03c67b16c12bd67e6835e4de01cd84baba53fb3d22294252dbb2ba854d1fe25f473b6ac8141392697bc6049d3865d9a00f909971e3b1903758e11b13a4661cf79080beac6d9ddb9113dfa788d2fc38a073b8d2717d0e28721f37dc0f7b6eb9a389f8050fac387ba3dedaf32210995534df5188982d431d0f6d93daa48b10ae7a337571f8bbcea59c9677789eedc2fcf2572f3d2ace9ae12b4817aa08d9541a423d0e60fd657f332c3fe47eef242e56715d25422971b6381a1e6a52bbae574da0077f83a535");
        EXPECT_EQ(bitsize(e), (std::size_t) 17);                       // 17-bit
        EXPECT_EQ(e, 0x10001);
    }

    // subsig
    {
        EXPECT_EQ(subsig -> get_type(), Signature_Type::SUBKEY_BINDING_SIGNATURE);
        EXPECT_EQ(subsig -> get_pka(), PKA::RSA_ENCRYPT_OR_SIGN);
        EXPECT_EQ(subsig -> get_hash(), Hash::SHA1);
        EXPECT_EQ(subsig -> get_left16(), "\x9a\xeb");
        EXPECT_EQ(bitsize(subsig -> get_mpi()[0]), (std::size_t) 2047);  // 2047-bit

        // subsig/hashed
        auto subsub = subsig -> get_hashed_subpackets();
        ASSERT_EQ(subsub.size(), (Tag2::Subpackets::size_type) 2);
        Subpacket::Ptr
                ss0 = subsub[0],
                ss1 = subsub[1];

        ASSERT_EQ(ss0 -> get_type(), Tag2Subpacket::SIGNATURE_CREATION_TIME);
        ASSERT_EQ(ss1 -> get_type(), Tag2Subpacket::KEY_FLAGS);

        Tag2Sub2::Ptr  subsub2  = std::dynamic_pointer_cast <Tag2Sub2>  (ss0);
        Tag2Sub27::Ptr subsub27 = std::dynamic_pointer_cast <Tag2Sub27> (ss1);
        // subsig/sub2
        {
            EXPECT_EQ(subsub2 -> get_time(), gen_time);                  // 2014-06-22T12:50:48 UTC
        }
        // subsig/sub27
        {
            EXPECT_EQ(subsub27 -> get_flags(), std::string(1, 4 | 8));
        }

        // subsig/unhashed
        auto uh_subsub = subsig -> get_unhashed_subpackets();
        ASSERT_EQ(uh_subsub.size(), (Tag2::Subpackets::size_type) 1);
        Subpacket::Ptr uhss0 = uh_subsub[0];
        ASSERT_EQ(uhss0 -> get_type(), Tag2Subpacket::ISSUER);
        Tag2Sub16::Ptr subsub16 = std::dynamic_pointer_cast <Tag2Sub16> (uhss0);
        // subsig/sub16
        {
            EXPECT_EQ(subsub16 -> get_keyid(), "\xd5\xd7\xda\x71\xc3\x54\x96\x0e");
        }
    }

}

TEST(PGP, private_key){
    PGPSecretKey pgp(GPG_PRIKEY_ALICE);

    auto packets = pgp.get_packets();
    ASSERT_EQ(packets.size(), (PGP::Packets::size_type) 5);

    Packet::Ptr
            p0 = packets[0],
            p1 = packets[1],
            p2 = packets[2],
            p3 = packets[3],
            p4 = packets[4];

    ASSERT_EQ(p0 -> get_tag(), Packet::SECRET_KEY);
    ASSERT_EQ(p1 -> get_tag(), Packet::USER_ID);
    ASSERT_EQ(p2 -> get_tag(), Packet::SIGNATURE);
    ASSERT_EQ(p3 -> get_tag(), Packet::SECRET_SUBKEY);
    ASSERT_EQ(p4 -> get_tag(), Packet::SIGNATURE);
    Tag5::Ptr  seckey = std::dynamic_pointer_cast <Tag5>  (p0);
    Tag13::Ptr userid = std::dynamic_pointer_cast <Tag13> (p1);
    Tag7::Ptr  subkey = std::dynamic_pointer_cast <Tag7>  (p3);
    Tag2::Ptr  pubsig = std::dynamic_pointer_cast <Tag2>  (p2),
               subsig = std::dynamic_pointer_cast <Tag2>  (p4);

    EXPECT_EQ(seckey -> get_version(), (uint8_t) 4);
    EXPECT_EQ(subkey -> get_version(), (uint8_t) 4);
    EXPECT_EQ(pubsig -> get_version(), (uint8_t) 4);
    EXPECT_EQ(subsig -> get_version(), (uint8_t) 4);
    EXPECT_EQ(userid -> get_version(), (uint8_t) 0);       // undefined

    EXPECT_EQ(seckey -> get_size(), (std::size_t) 958);
    EXPECT_EQ(userid -> get_size(), (std::size_t) 36);
    EXPECT_EQ(pubsig -> get_size(), (std::size_t) 312);
    EXPECT_EQ(subkey -> get_size(), (std::size_t) 958);
    EXPECT_EQ(subsig -> get_size(), (std::size_t) 287);

    time_t gen_time = get_utc(2014, 6, 22, 12, 50, 48);

    // seckey
    {
        EXPECT_EQ(seckey -> get_time(), gen_time);         // 2014-06-22T12:50:48 UTC
        EXPECT_EQ(seckey -> get_pka(), PKA::RSA_ENCRYPT_OR_SIGN);
        auto mpi = seckey -> get_mpi();
        auto n = mpi[0], e = mpi[1];
        EXPECT_EQ(bitsize(n), (std::size_t) 2048);         // 2048-bit
        EXPECT_EQ(mpitohex(n), "bc047e94d471f3ccbd525d6a6f8e17f7b1f00527c722c3913ce787fbd0090e3af8be7e59410f63b3983a9507b761045c11510e62f5a8cfbcdc180976a4c225737b8e06d8531f38c6eaa996954d5521a6763231f07c2b43605d052abdf39d6c668ac94bc89f543052d050530c70c48a49a970867c00178f9076dd0e151d254632767b2926e9baa22c6d0c213f1f45de74991396d7e8d10508cf679139410ab311b1279dd3c0d37facca54d523cd14a3df488eb8f592c5a19bcfede67c8170815c588adf39d188197da40492aac5b183c303f6ef23b0b5e48ff73b2d806afb0fb4f16ba32769249d3a7ca0ef0b9b3d57852dc9a979b6d56f3dc170e28dcb2e536d");
        EXPECT_EQ(bitsize(e), (std::size_t) 17);           // 17-bit
        EXPECT_EQ(e, 0x10001);
        EXPECT_EQ(seckey -> get_sym(), Sym::CAST5);
        EXPECT_EQ(seckey -> get_IV(), "\x47\xdb\x0a\x37\x11\x76\xb3\x5d");
        auto secs2k = seckey -> get_s2k();
        EXPECT_EQ(secs2k -> get_type(), S2K::ITERATED_AND_SALTED_S2K);
        EXPECT_EQ(secs2k -> get_hash(), Hash::SHA1);
        S2K3::Ptr secs2k3 = std::dynamic_pointer_cast <S2K3> (secs2k);
        EXPECT_EQ(secs2k3 -> get_count(), (uint8_t) 96);
        auto secmpi = seckey -> decrypt_secret_keys(PASSPHRASE);
        EXPECT_EQ(secmpi.size(), (PKA::Values::size_type) 4);
        EXPECT_EQ(mpitohex(secmpi[0]), "03949bbb19be693235e62b7ef33fcd6f5813afb7d8db542c99a3921eed10a3153050c993e30dbe6c454939836d27bb5f2c137323899bccd48fd909efe5b93b60a645daaf6aa3d1b8ee08fed72d56158bd13cb62c73e34ba0ed82f6ba76390eff43ea71f110ae7e814ad3fa5e8007dd5750acc92873aaff320ea56cf0ade4dc7994ac78d9dfc567ead2589f514ac4a95d2a28685d1f593129f7f82fdaca2e4e87b4b223ca3d6c742370bfba2a4954b1c7bcf4290addad26c2a52ea4a5d664a8c32cf729bb1c783fa817ef50c5432a3c1c73ef9d1e08ecf9780d5f3c8667ade01f397270b2919d632cba1ccd4c0861cb8420f4eabe8606115342657a281f1051d1");
        EXPECT_EQ(mpitohex(secmpi[1]), "d03b3727809678a98fb4f94f9fde836efeaacafefd721ebb83c90dfebcc169a88944859afb2c4154c20d45a155d85bf692be56c1778b0bd94b77fd878d81bbe5584fbb28e716785821b1f4e0a3bffb7bc812c51394dc803d53afa261745092ed3169fcc7e2d125f2595a1555efc5f350be6654b050057839be3fc3ac1719453d");
        EXPECT_EQ(mpitohex(secmpi[2]), "e7262ff9b96de7b93a9977edebd1b424217c8e1edce2e1ac9e38493ef5e727b4fbbc64312e0a48823fa5e71292d939e724f2c5d32eed544be5e7bc3421b4b6031cd65b1d8531d24e1d44bd282edddb20f58abdd78722a18e4f62fde869381f5e6040e1163e399f7b7b614f17bb51038c23c57b1d87241d97dbc7e4b85e1909f1");
        EXPECT_EQ(mpitohex(secmpi[3]), "a5b011afc09d933d7f75b58e750bee1f05bf95d7bc354d3989eaa58cbdf85c367536b11dd29e016fe90f419288765e50af6e00a96660169716313f8d4080ce407cbad43a912e23170552d97a0465ab90a0a6b879a85bef0c2bbae100cbfc2927a01a0842fe8c2c6234149b35c05075438f7f4e2a3d5f19f427f423b868c0dad1");
    }

    // userid
    {
        EXPECT_EQ(userid -> raw(), "alice (test key) <alice@example.com>");
    }

    // pubsig (same as test_gpg_public_key)
    {
        EXPECT_EQ(pubsig -> get_type(), Signature_Type::POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET);
        EXPECT_EQ(pubsig -> get_pka(), PKA::RSA_ENCRYPT_OR_SIGN);
        EXPECT_EQ(pubsig -> get_hash(), Hash::SHA1);
        EXPECT_EQ(pubsig -> get_left16(), "\x04\x5e");
        auto mpi = pubsig -> get_mpi();
        ASSERT_EQ(mpi.size(), (PKA::Values::size_type) 1);
        EXPECT_EQ(bitsize(mpi[0]), (std::size_t) 2047);    // 2047-bit
        EXPECT_EQ(mpitohex(mpi[0]), "688a18a258f866cf50f1c938dc15b11298da0bfbd680241f52545af5023722858cdfb579da22e66dae36dff9a817f797192e95b7074bab49381acb837f1216d4e8e3c2de2fb5547a515b5236823bcb4b3bca1a68455fa984c4dc21b1a5af2308aea580c0ae2ca3f5db343beaa559524702d09e40d1923314ef0f15646acec91b9c6d9cba9d9b87fa78626a522ae1520f0aed361df00f8191a9ecb1fb12732e9f6e5e1c4bece397e4dcfbacd41918882c2dfa75b98b54587f0cd61195bdce41b690329a746c6e37b7e2ef9b06206bf280ff93ec0b891929790492a9971acaa9e7e141585ca41800dd462b6f8235c0f1e0b691a5054da8f90295f5949e22fb5e5c");
        // pubsig/hashed
        auto pubsub = pubsig -> get_hashed_subpackets();
        ASSERT_EQ(pubsub.size(), (Tag2::Subpackets::size_type) 7);
        Subpacket::Ptr
                ps0 = pubsub[0],
                ps1 = pubsub[1],
                ps2 = pubsub[2],
                ps3 = pubsub[3],
                ps4 = pubsub[4],
                ps5 = pubsub[5],
                ps6 = pubsub[6];

        ASSERT_EQ(ps0 -> get_type(), Tag2Subpacket::SIGNATURE_CREATION_TIME);
        ASSERT_EQ(ps1 -> get_type(), Tag2Subpacket::KEY_FLAGS);
        ASSERT_EQ(ps2 -> get_type(), Tag2Subpacket::PREFERRED_SYMMETRIC_ALGORITHMS);
        ASSERT_EQ(ps3 -> get_type(), Tag2Subpacket::PREFERRED_HASH_ALGORITHMS);
        ASSERT_EQ(ps4 -> get_type(), Tag2Subpacket::PREFERRED_COMPRESSION_ALGORITHMS);
        ASSERT_EQ(ps5 -> get_type(), Tag2Subpacket::FEATURES);
        ASSERT_EQ(ps6 -> get_type(), Tag2Subpacket::KEY_SERVER_PREFERENCES);
        Tag2Sub2::Ptr  pubsub2  = std::dynamic_pointer_cast <Tag2Sub2>  (ps0);
        Tag2Sub27::Ptr pubsub27 = std::dynamic_pointer_cast <Tag2Sub27> (ps1);
        Tag2Sub11::Ptr pubsub11 = std::dynamic_pointer_cast <Tag2Sub11> (ps2);
        Tag2Sub21::Ptr pubsub21 = std::dynamic_pointer_cast <Tag2Sub21> (ps3);
        Tag2Sub22::Ptr pubsub22 = std::dynamic_pointer_cast <Tag2Sub22> (ps4);
        Tag2Sub30::Ptr pubsub30 = std::dynamic_pointer_cast <Tag2Sub30> (ps5);
        Tag2Sub23::Ptr pubsub23 = std::dynamic_pointer_cast <Tag2Sub23> (ps6);

        // pubsig/sub2
        {
            EXPECT_EQ(pubsub2 -> get_time(), gen_time); // 2014-06-22T12:50:48 UTC
        }
        // pubsig/sub27
        {
            EXPECT_EQ(pubsub27 -> get_flags(), std::string(1, 1 | 2));
        }
        // pubsig/sub11
        {
            std::string psa = pubsub11 -> get_psa();
            EXPECT_EQ(psa.size(), (std::string::size_type) 5);
            EXPECT_NE(psa.find(Sym::AES128),    std::string::npos);
            EXPECT_NE(psa.find(Sym::AES192),    std::string::npos);
            EXPECT_NE(psa.find(Sym::AES256),    std::string::npos);
            EXPECT_NE(psa.find(Sym::CAST5),     std::string::npos);
            EXPECT_NE(psa.find(Sym::TRIPLEDES), std::string::npos);
        }
        // pubsig/sub21
        {
            std::string pha = pubsub21 -> get_pha();
            EXPECT_EQ(pha.size(), (std::string::size_type) 5);
            EXPECT_NE(pha.find(Hash::SHA256), std::string::npos);
            EXPECT_NE(pha.find(Hash::SHA1),   std::string::npos);
            EXPECT_NE(pha.find(Hash::SHA384), std::string::npos);
            EXPECT_NE(pha.find(Hash::SHA512), std::string::npos);
            EXPECT_NE(pha.find(Hash::SHA224), std::string::npos);
        }
        // pubsig/sub22
        {
            std::string pca = pubsub22 -> get_pca();
            EXPECT_EQ(pca.size(), (std::string::size_type) 3);
            EXPECT_NE(pca.find(Compression::ZLIB),  std::string::npos);
            EXPECT_NE(pca.find(Compression::BZIP2), std::string::npos);
            EXPECT_NE(pca.find(Compression::ZIP),   std::string::npos);
        }
        // pubsig/sub30
        {
            EXPECT_EQ(pubsub30 -> get_flags().size(), (std::string::size_type) 1);
            EXPECT_EQ(pubsub30 -> get_flags()[0], Features_Flags::MODIFICATION_DETECTION);
        }
        // pubsig/sub23
        {
            EXPECT_EQ(pubsub23 -> get_flags().size(), (std::string::size_type) 1);
            EXPECT_EQ(static_cast <uint8_t> (pubsub23 -> get_flags()[0]), Key_Server_Preferences::NO_MODIFY);
        }

        // pubsig/unhashed
        auto uh_pubsub = pubsig -> get_unhashed_subpackets();
        ASSERT_EQ(uh_pubsub.size(), (Tag2::Subpackets::size_type) 1);
        Subpacket::Ptr uhps0 = uh_pubsub[0];
        ASSERT_EQ(uhps0 -> get_type(), Tag2Subpacket::ISSUER);
        Tag2Sub16::Ptr pubsub16 = std::dynamic_pointer_cast <Tag2Sub16> (uhps0);
        // pubsig/sub16
        {
            EXPECT_EQ(pubsub16 -> get_keyid(), "\xd5\xd7\xda\x71\xc3\x54\x96\x0e");
        }
    }

    // subkey
    {
        EXPECT_EQ(subkey -> get_time(), gen_time); // 2014-06-22T12:50:48 UTC
        EXPECT_EQ(subkey -> get_pka(), PKA::RSA_ENCRYPT_OR_SIGN);
        auto mpi = subkey -> get_mpi();
        auto n = mpi[0], e = mpi[1];
        EXPECT_EQ(bitsize(n), (std::size_t) 2048); // 2048-bit
        EXPECT_EQ(mpitohex(n), "d98aac4e3f499e2264aebd71ea0e7d8a8d4690ff73d09125cd197892f1bb59492b8523dc5e4a0b9e0702babf65a71113d96a7ba2ee37cdc2ae8b0b03c67b16c12bd67e6835e4de01cd84baba53fb3d22294252dbb2ba854d1fe25f473b6ac8141392697bc6049d3865d9a00f909971e3b1903758e11b13a4661cf79080beac6d9ddb9113dfa788d2fc38a073b8d2717d0e28721f37dc0f7b6eb9a389f8050fac387ba3dedaf32210995534df5188982d431d0f6d93daa48b10ae7a337571f8bbcea59c9677789eedc2fcf2572f3d2ace9ae12b4817aa08d9541a423d0e60fd657f332c3fe47eef242e56715d25422971b6381a1e6a52bbae574da0077f83a535");
        EXPECT_EQ(bitsize(e), (std::size_t) 17);   // 17-bit
        EXPECT_EQ(e, 0x10001);
        EXPECT_EQ(subkey -> get_sym(), Sym::CAST5);
        EXPECT_EQ(subkey -> get_IV(), "\x22\x01\xe4\x2a\xc6\x81\x4d\x35");
        auto subs2k = subkey -> get_s2k();
        EXPECT_EQ(subs2k -> get_type(), S2K::ITERATED_AND_SALTED_S2K);
        EXPECT_EQ(subs2k -> get_hash(), Hash::SHA1);
        S2K3::Ptr subs2k3 = std::dynamic_pointer_cast <S2K3> (subs2k);
        EXPECT_EQ(subs2k3 -> get_count(), (uint8_t) 96);
        auto secmpi = subkey -> decrypt_secret_keys(PASSPHRASE);
        EXPECT_EQ(secmpi.size(), (PKA::Values::size_type) 4);
        EXPECT_EQ(mpitohex(secmpi[0]), "6275226e19b3ba880b7490d6855e0090dc47136a22a343864dd118e2bcd893dd0b7eeb4f9a373e11cc4f7e7110d36fe5c171b1ba78c1b5f5466534db851201a6f52dd3b15baf1591d05021e92208644f594824d33d8db0b64ad77c52f37fed4534e47fac5edf88bed54e0d64ee079ce5b66034c49bc152ff059e57a7c5b546b9526a98fa7d2371d8843887c7708a5a5db82f3520cb7d784602b145e4c3de287fc2dd50a9b9c99d34176852e1024cf1eac2d9039b5a690991ee2f1b178c308587f62801955d3254530203b039823aec6d50bd40d791711fff815c76cd99164725cd43f4c2134c1053f63281d4a6d210809f6b686a3db45d66ebd85ac16883e413");
        EXPECT_EQ(mpitohex(secmpi[1]), "ebc63b9c2c5002d77f3f3261ce3ebdd4710827b180f0a2b5b847c2e5e6365903fc8ae73078666737850c0575d1ef558b0d77e3039f1e4cef6a97e90ccc70bec4459f4140725d98f2d275f81da1326b34cf1e0b0b69466e878e2c98823732ea5baa0cff7d687bf44590a0bab69f6d7182dcfb8ec20197fe9533730ce0549f991b");
        EXPECT_EQ(mpitohex(secmpi[2]), "ec3409ddb6f104384a7f4788ba73164d8420bdbc240d815c6e615603955ca128a388c21c0c19fe42be806922c2708d37efefd57a52f1fb777cfad002f2ba4f6c4c7119734340f13639b02a5c66d9b98048388ab3e97fca8f47fb07d360ed629762c045929f4f60c37c34a52ae75a12be68cb9644d7867de03029c3dccc736fef");
        EXPECT_EQ(mpitohex(secmpi[3]), "0547d7351f3047b5d4728cfed246eef218e4d0840d5f5edb9faf723da93bbb914e806a8ea569889eada1a37a6dd69da1c7f6f2e21d8fc6622dc759adb97a3e4003fcd7a499bcecebf9b7f4be958c3486501810ce321b2c343d1d19aae7f6b6454b5a7a5c551986f49e904b63a6f7cc32ccafa78bb7a7696d627ba67489cdcc89");
    }

    // subsig (same as test_gpg_public_key)
    {
        EXPECT_EQ(subsig -> get_type(), Signature_Type::SUBKEY_BINDING_SIGNATURE);
        EXPECT_EQ(subsig -> get_pka(), PKA::RSA_ENCRYPT_OR_SIGN);
        EXPECT_EQ(subsig -> get_hash(), Hash::SHA1);
        EXPECT_EQ(subsig -> get_left16(), "\x9a\xeb");
        EXPECT_EQ(bitsize(subsig -> get_mpi()[0]), (std::size_t) 2047); // 2047-bit

        // subsig/hashed
        auto subsub = subsig -> get_hashed_subpackets();
        ASSERT_EQ(subsub.size(), (Tag2::Subpackets::size_type) 2);
        Subpacket::Ptr
                ss0 = subsub[0],
                ss1 = subsub[1];

        ASSERT_EQ(ss0 -> get_type(), (uint8_t) 2);
        ASSERT_EQ(ss1 -> get_type(), (uint8_t) 27);

        Tag2Sub2::Ptr  subsub2  = std::dynamic_pointer_cast <Tag2Sub2>  (ss0);
        Tag2Sub27::Ptr subsub27 = std::dynamic_pointer_cast <Tag2Sub27> (ss1);
        // subsig/sub2
        {
            EXPECT_EQ(subsub2 -> get_time(), gen_time); // 2014-06-22T12:50:48 UTC
        }
        // subsig/sub27
        {
            EXPECT_EQ(subsub27 -> get_flags(), std::string(1, 4 | 8));
        }

        // subsig/unhashed
        auto uh_subsub = subsig -> get_unhashed_subpackets();
        ASSERT_EQ(uh_subsub.size(), (Tag2::Subpackets::size_type) 1);
        Subpacket::Ptr uhss0 = uh_subsub[0];
        ASSERT_EQ(uhss0 -> get_type(), Tag2Subpacket::ISSUER);
        Tag2Sub16::Ptr subsub16 = std::dynamic_pointer_cast <Tag2Sub16> (uhss0);
        // subsig/sub16
        {
            EXPECT_EQ(subsub16 -> get_keyid(), "\xd5\xd7\xda\x71\xc3\x54\x96\x0e");
        }
    }
}

TEST(PGP, revoke){
    std::string in = GPG_REVOKE3_ALICE;
    PGPRevocationCertificate pgp(in);

    auto packets = pgp.get_packets();
    ASSERT_EQ(packets.size(), (PGP::Packets::size_type) 1);

    Packet::Ptr p0 = packets[0];

    ASSERT_EQ(p0 -> get_tag(), (uint8_t) 2);
    Tag2::Ptr revsig = std::dynamic_pointer_cast <Tag2> (p0);

    EXPECT_EQ(revsig -> get_version(), (uint8_t) 4);
    EXPECT_EQ(revsig -> get_size(), (std::size_t) 287);

    EXPECT_EQ(revsig -> get_type(), Signature_Type::KEY_REVOCATION_SIGNATURE);
    EXPECT_EQ(revsig -> get_pka(), PKA::RSA_ENCRYPT_OR_SIGN);
    EXPECT_EQ(revsig -> get_hash(), Hash::SHA1);
    EXPECT_EQ(revsig -> get_left16(), "\xcf\xb9");

    auto mpi = revsig -> get_mpi();
    ASSERT_EQ(mpi.size(), (PKA::Values::size_type) 1);

    auto sign = mpi[0];
    EXPECT_EQ(bitsize(sign), (std::size_t) 2045);
    EXPECT_EQ(mpitohex(sign), "133edac0fa9b187e05f8ce8dade82f31d3a266190f911b79aed0974952601b3effeed8a1a1dca9f742292a308be8cac43ff2c801ef901c06c6c6a520736dfc4b02c8f92af7a99a03f89d3d62df9844cb6271e409200a7fb6d2e29fe3e72be5305004a39765bf7f02be6dcde47e44131e5529d397592432a74decc6db6cd627848f1535a6166103e6a17f99256fead668fdeb37a72c3f0bc0c4795db324da138d38c37011d5b071ecce77fb84da464eaa6a75b2e1ab6ffa6653b0539149e5f92cfb0389d843f26cabcc41f0d623966734b2a7fa110430b29f1a7854ae5affbf9e228bbb440152242542585c7a38b95a541a8d9afccffd6c227b0a11bcd60b2bc7");

    // hashed
    {
        auto hashed = revsig -> get_hashed_subpackets();
        ASSERT_EQ(hashed.size(), (std::size_t) 2);

        Subpacket::Ptr
                s0 = hashed[0],
                s1 = hashed[1];

        ASSERT_EQ(s0 -> get_type(), Tag2Subpacket::SIGNATURE_CREATION_TIME);
        ASSERT_EQ(s1 -> get_type(), Tag2Subpacket::REASON_FOR_REVOCATION);

        Tag2Sub2::Ptr sub2   = std::dynamic_pointer_cast <Tag2Sub2>  (s0);
        Tag2Sub29::Ptr sub29 = std::dynamic_pointer_cast <Tag2Sub29> (s1);

        // sub2
        {
            EXPECT_EQ(sub2 -> get_time(), get_utc(2014, 6, 22, 13, 03, 49));
        }
        // sub29
        {
            EXPECT_EQ(sub29 -> get_code(), Revoke::KEY_IS_NO_LONGER_USED);
            EXPECT_EQ(sub29 -> get_reason(), ""); // (empty string)
        }
    }
    // unhashed
    {
        auto unhashed = revsig -> get_unhashed_subpackets();
        ASSERT_EQ(unhashed.size(), (Tag2::Subpackets::size_type) 1);

        Subpacket::Ptr s0 = unhashed[0];
        ASSERT_EQ(s0 -> get_type(), Tag2Subpacket::ISSUER);

        Tag2Sub16::Ptr sub16 = std::dynamic_pointer_cast <Tag2Sub16> (s0);
        EXPECT_EQ(sub16 -> get_keyid(), "\xd5\xd7\xda\x71\xc3\x54\x96\x0e");
    }


}

TEST(PGP, encrypt_decrypt_pka_mdc){
    std::string error;
    const PGPSecretKey pri(GPG_PRIKEY_ALICE);
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
    const PGPSecretKey pri(GPG_PRIKEY_ALICE);
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
    const PGPSecretKey pri(GPG_PRIKEY_BOB);

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

    const PGPSecretKey pri(GPG_PRIKEY_ALICE);
    const SignArgs sign_args(pri, PASSPHRASE);
    const PGPDetachedSignature sig = sign_detached_signature(sign_args, MESSAGE, error);
    EXPECT_EQ(verify_detached_signature(pri, MESSAGE, sig, error), true);
}

TEST(PGP, sign_verify_binary){
    std::string error;

    const PGPSecretKey pri(GPG_PRIKEY_ALICE);
    const SignArgs sign_args(pri, PASSPHRASE);
    const PGPDetachedSignature sig = sign_binary(sign_args, "", MESSAGE, Compression::ZLIB, error);
    EXPECT_EQ(verify_binary(pri, sig, error), true);
}

TEST(PGP, clearsign){
    PGPCleartextSignature pgp(GPG_CLEARSIGN_ALICE);
    EXPECT_EQ(pgp.get_message(), "The magic words are squeamish ossifrage");

    auto key = pgp.get_sig();
    auto packets = key.get_packets();

    EXPECT_EQ(packets.size(), (PGP::Packets::size_type) 1);

    Packet::Ptr p0 = packets[0];
    ASSERT_EQ(p0 -> get_tag(), Packet::SIGNATURE);

    Tag2::Ptr tag2 = std::dynamic_pointer_cast <Tag2> (p0);

    EXPECT_EQ(tag2 -> get_version(), (uint8_t) 4);

    EXPECT_EQ(tag2 -> get_size(), (std::size_t) 284);

    EXPECT_EQ(tag2 -> get_pka(), PKA::RSA_ENCRYPT_OR_SIGN);
    EXPECT_EQ(tag2 -> get_hash(), Hash::SHA1);
    EXPECT_EQ(tag2 -> get_left16(), "\x77\x8e");

    auto mpi = tag2 -> get_mpi();
    ASSERT_EQ(mpi.size(), (PKA::Values::size_type) 1);
    auto sign = mpi[0];
    EXPECT_EQ(bitsize(sign), (std::size_t) 2047);
    EXPECT_EQ(mpitohex(sign), "4d1df9039259b42782d30c91e29ae9f7ac20e623e86c25e069ca441afc4a1cec30c9486c1a17799e8b1d39dcb8240b74269d083ad62f09232195fef84abca886c45f5263beaa02dde4b0a3ea4ff659d3bcaab5509a9d265e6326d560f8d0662ec07347fbf360e2421f851f12d923ceac84139245747ef3180b836eb4785428c9ea6fe5842e56d6ba7582b278b5ca68ad6bcb7a630568f800517264ddce690c96ab5925603be83b55207df45483c9cf57f88556e5a806910fb213e5cb3ee02bc45e4e4a894ebaec6967555cfae7615657a239a4523f56d0e399ccd35118d2b4daca2180b0fe24d8d258c59f8203dcb8579f8980802321ab274992bcf23d9d0095");

    // hashed
    {
        auto hashed = tag2 -> get_hashed_subpackets();
        ASSERT_EQ(hashed.size(), (std::size_t) 1);

        Subpacket::Ptr s0 = hashed[0];
        ASSERT_EQ(s0 -> get_type(), Tag2Subpacket::SIGNATURE_CREATION_TIME);

        Tag2Sub2::Ptr sub2 = std::dynamic_pointer_cast <Tag2Sub2> (s0);
        EXPECT_EQ(sub2 -> get_time(), get_utc(2014, 06, 22, 13, 05, 41));
    }
    // unhashed
    {
        auto unhashed = tag2 -> get_unhashed_subpackets();
        ASSERT_EQ(unhashed.size(), (Tag2::Subpackets::size_type) 1);

        Subpacket::Ptr s0 = unhashed[0];
        ASSERT_EQ(s0 -> get_type(), Tag2Subpacket::ISSUER);

        Tag2Sub16::Ptr sub16 = std::dynamic_pointer_cast <Tag2Sub16> (s0);
        EXPECT_EQ(sub16 -> get_keyid(), "\xd5\xd7\xda\x71\xc3\x54\x96\x0e");
    }

}

TEST(PGP, verify_primary_key){
    std::string error;

    const PGPPublicKey pub(GPG_PUBKEY_ALICE);
    const PGPSecretKey pri(GPG_PRIKEY_ALICE);

    EXPECT_EQ(verify_primary_key(pub, pub, error), true);
    EXPECT_EQ(verify_primary_key(pub, pri, error), true);
    EXPECT_EQ(verify_primary_key(pri, pub, error), true);
    EXPECT_EQ(verify_primary_key(pri, pri, error), true);
}
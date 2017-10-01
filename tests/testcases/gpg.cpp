#include <iostream>
#include <ctime>
#include <sstream>

#include <gtest/gtest.h>

#include "OpenPGP.h"

#include "testvectors/msg.h"
#include "testvectors/pass.h"
#include "testvectors/read_pgp.h"

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

TEST(gpg, public_key){

    OpenPGP::PublicKey pub;
    ASSERT_EQ(read_pgp <OpenPGP::PublicKey> ("Alicepub", pub), true);

    // read public key into SecretKey
    {
        OpenPGP::SecretKey pri;
        EXPECT_EQ(read_pgp <OpenPGP::SecretKey> ("Alicepub", pri), false);
    }

    ASSERT_EQ(pub.keyid(), unhexlify("d5d7da71c354960e"));
    ASSERT_EQ(pub.fingerprint(), unhexlify("4b3292e956b577ad703443f4d5d7da71c354960e"));

    const OpenPGP::PGP::Packets packets = pub.get_packets();
    ASSERT_EQ(packets.size(), (OpenPGP::PGP::Packets::size_type) 5);

    ASSERT_EQ(packets[0] -> get_tag(), OpenPGP::Packet::PUBLIC_KEY);
    ASSERT_EQ(packets[1] -> get_tag(), OpenPGP::Packet::USER_ID);
    ASSERT_EQ(packets[2] -> get_tag(), OpenPGP::Packet::SIGNATURE);
    ASSERT_EQ(packets[3] -> get_tag(), OpenPGP::Packet::PUBLIC_SUBKEY);
    ASSERT_EQ(packets[4] -> get_tag(), OpenPGP::Packet::SIGNATURE);
    const OpenPGP::Packet::Tag6::Ptr  pubkey = std::dynamic_pointer_cast <OpenPGP::Packet::Tag6>  (packets[0]);
    const OpenPGP::Packet::Tag13::Ptr userid = std::dynamic_pointer_cast <OpenPGP::Packet::Tag13> (packets[1]);
    const OpenPGP::Packet::Tag2::Ptr  pubsig = std::dynamic_pointer_cast <OpenPGP::Packet::Tag2>  (packets[2]);
    const OpenPGP::Packet::Tag14::Ptr subkey = std::dynamic_pointer_cast <OpenPGP::Packet::Tag14> (packets[3]);
    const OpenPGP::Packet::Tag2::Ptr  subsig = std::dynamic_pointer_cast <OpenPGP::Packet::Tag2>  (packets[4]);

    EXPECT_EQ(pubkey -> get_version(), (uint8_t) 4);
    EXPECT_EQ(subkey -> get_version(), (uint8_t) 4);
    EXPECT_EQ(pubsig -> get_version(), (uint8_t) 4);
    EXPECT_EQ(subsig -> get_version(), (uint8_t) 4);

    EXPECT_EQ(pubkey -> get_size(), (std::size_t) 269);
    EXPECT_EQ(userid -> get_size(), (std::size_t)  36);
    EXPECT_EQ(pubsig -> get_size(), (std::size_t) 312);
    EXPECT_EQ(subkey -> get_size(), (std::size_t) 269);
    EXPECT_EQ(subsig -> get_size(), (std::size_t) 287);

    const uint32_t gen_time = get_utc(2014, 6, 22, 12, 50, 48);

    // pubkey
    {
        EXPECT_EQ(pubkey -> get_time(), gen_time);                       // 2014-06-22T12:50:48 UTC
        EXPECT_EQ(pubkey -> get_pka(), OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN);
        const OpenPGP::PKA::Values mpi = pubkey -> get_mpi();
        EXPECT_EQ(OpenPGP::bitsize(mpi[0]), (std::size_t) 2048);         // 2048-bit
        EXPECT_EQ(OpenPGP::mpitohex(mpi[0]), "bc047e94d471f3ccbd525d6a6f8e17f7b1f00527c722c3913ce787fbd0090e3af8be7e59410f63b3983a9507b761045c11510e62f5a8cfbcdc180976a4c225737b8e06d8531f38c6eaa996954d5521a6763231f07c2b43605d052abdf39d6c668ac94bc89f543052d050530c70c48a49a970867c00178f9076dd0e151d254632767b2926e9baa22c6d0c213f1f45de74991396d7e8d10508cf679139410ab311b1279dd3c0d37facca54d523cd14a3df488eb8f592c5a19bcfede67c8170815c588adf39d188197da40492aac5b183c303f6ef23b0b5e48ff73b2d806afb0fb4f16ba32769249d3a7ca0ef0b9b3d57852dc9a979b6d56f3dc170e28dcb2e536d");
        EXPECT_EQ(OpenPGP::bitsize(mpi[1]), (std::size_t) 17);           // 17-bit
        EXPECT_EQ(mpi[1], 0x10001);
    }

    // userid
    {
        EXPECT_EQ(userid -> raw(), "alice (test key) <alice@example.com>");
    }

    // pubsig
    {
        EXPECT_EQ(pubsig -> get_type(), OpenPGP::Signature_Type::POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET);
        EXPECT_EQ(pubsig -> get_pka(), OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN);
        EXPECT_EQ(pubsig -> get_hash(), OpenPGP::Hash::ID::SHA1);
        EXPECT_EQ(pubsig -> get_left16(), "\x04\x5e");
        const OpenPGP::PKA::Values mpi = pubsig -> get_mpi();
        ASSERT_EQ(mpi.size(), (OpenPGP::PKA::Values::size_type) 1);
        EXPECT_EQ(OpenPGP::bitsize(mpi[0]), (std::size_t) 2047);         // 2047-bit
        EXPECT_EQ(OpenPGP::mpitohex(mpi[0]), "688a18a258f866cf50f1c938dc15b11298da0bfbd680241f52545af5023722858cdfb579da22e66dae36dff9a817f797192e95b7074bab49381acb837f1216d4e8e3c2de2fb5547a515b5236823bcb4b3bca1a68455fa984c4dc21b1a5af2308aea580c0ae2ca3f5db343beaa559524702d09e40d1923314ef0f15646acec91b9c6d9cba9d9b87fa78626a522ae1520f0aed361df00f8191a9ecb1fb12732e9f6e5e1c4bece397e4dcfbacd41918882c2dfa75b98b54587f0cd61195bdce41b690329a746c6e37b7e2ef9b06206bf280ff93ec0b891929790492a9971acaa9e7e141585ca41800dd462b6f8235c0f1e0b691a5054da8f90295f5949e22fb5e5c");
        // pubsig/hashed
        const OpenPGP::Packet::Tag2::Subpackets pubsub = pubsig -> get_hashed_subpackets();
        ASSERT_EQ(pubsub.size(), (OpenPGP::Packet::Tag2::Subpackets::size_type) 7);

        ASSERT_EQ(pubsub[0] -> get_type(), OpenPGP::Subpacket::Tag2::SIGNATURE_CREATION_TIME);
        ASSERT_EQ(pubsub[1] -> get_type(), OpenPGP::Subpacket::Tag2::KEY_FLAGS);
        ASSERT_EQ(pubsub[2] -> get_type(), OpenPGP::Subpacket::Tag2::PREFERRED_SYMMETRIC_ALGORITHMS);
        ASSERT_EQ(pubsub[3] -> get_type(), OpenPGP::Subpacket::Tag2::PREFERRED_HASH_ALGORITHMS);
        ASSERT_EQ(pubsub[4] -> get_type(), OpenPGP::Subpacket::Tag2::PREFERRED_COMPRESSION_ALGORITHMS);
        ASSERT_EQ(pubsub[5] -> get_type(), OpenPGP::Subpacket::Tag2::FEATURES);
        ASSERT_EQ(pubsub[6] -> get_type(), OpenPGP::Subpacket::Tag2::KEY_SERVER_PREFERENCES);

        // pubsig/sub2
        {
            const OpenPGP::Subpacket::Tag2::Sub2::Ptr pubsub2 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub2> (pubsub[0]);
            EXPECT_EQ(pubsub2 -> get_time(), gen_time);         // 2014-06-22T12:50:48 UTC
        }

        // pubsig/sub27
        {
            const OpenPGP::Subpacket::Tag2::Sub27::Ptr pubsub27 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub27> (pubsub[1]);
            EXPECT_EQ(pubsub27 -> get_flags(), std::string(1, 1 | 2));
        }

        // pubsig/sub11
        {
            const OpenPGP::Subpacket::Tag2::Sub11::Ptr pubsub11 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub11> (pubsub[2]);
            std::string psa = pubsub11 -> get_psa();
            EXPECT_EQ(psa.size(), (std::string::size_type) 5);
            EXPECT_NE(psa.find(OpenPGP::Sym::ID::AES256),    std::string::npos);
            EXPECT_NE(psa.find(OpenPGP::Sym::ID::AES192),    std::string::npos);
            EXPECT_NE(psa.find(OpenPGP::Sym::ID::AES128),    std::string::npos);
            EXPECT_NE(psa.find(OpenPGP::Sym::ID::CAST5),     std::string::npos);
            EXPECT_NE(psa.find(OpenPGP::Sym::ID::TRIPLEDES), std::string::npos);
        }

        // pubsig/sub21
        {
            const OpenPGP::Subpacket::Tag2::Sub21::Ptr pubsub21 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub21> (pubsub[3]);
            std::string pha = pubsub21 -> get_pha();
            EXPECT_EQ(pha.size(), (std::string::size_type) 5);
            EXPECT_NE(pha.find(OpenPGP::Hash::ID::SHA256), std::string::npos);
            EXPECT_NE(pha.find(OpenPGP::Hash::ID::SHA1),   std::string::npos);
            EXPECT_NE(pha.find(OpenPGP::Hash::ID::SHA384), std::string::npos);
            EXPECT_NE(pha.find(OpenPGP::Hash::ID::SHA512), std::string::npos);
            EXPECT_NE(pha.find(OpenPGP::Hash::ID::SHA224), std::string::npos);
        }

        // pubsig/sub22
        {
            const OpenPGP::Subpacket::Tag2::Sub22::Ptr pubsub22 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub22> (pubsub[4]);
            std::string pca = pubsub22 -> get_pca();
            EXPECT_EQ(pca.size(), (std::string::size_type) 3);
            EXPECT_NE(pca.find(OpenPGP::Compression::ID::ZLIB),  std::string::npos);
            EXPECT_NE(pca.find(OpenPGP::Compression::ID::BZIP2), std::string::npos);
            EXPECT_NE(pca.find(OpenPGP::Compression::ID::ZIP),   std::string::npos);
        }

        // pubsig/sub30
        {
            const OpenPGP::Subpacket::Tag2::Sub30::Ptr pubsub30 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub30> (pubsub[5]);
            EXPECT_EQ(pubsub30 -> get_flags().size(), (std::string::size_type) 1);
            EXPECT_EQ(pubsub30 -> get_flags()[0], OpenPGP::Subpacket::Tag2::Features_Flags::MODIFICATION_DETECTION);
        }

        // pubsig/sub23
        {
            const OpenPGP::Subpacket::Tag2::Sub23::Ptr pubsub23 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub23> (pubsub[6]);
            EXPECT_EQ(pubsub23 -> get_flags().size(), (std::string::size_type) 1);
            EXPECT_EQ(static_cast <uint8_t> (pubsub23 -> get_flags()[0]), OpenPGP::Subpacket::Tag2::Key_Server_Preferences::NO_MODIFY);
        }

        // pubsig/unhashed
        const OpenPGP::Packet::Tag2::Subpackets uh_pubsub = pubsig -> get_unhashed_subpackets();
        ASSERT_EQ(uh_pubsub.size(), (OpenPGP::Packet::Tag2::Subpackets::size_type) 1);
        const OpenPGP::Subpacket::Tag2::Sub::Ptr uhps0 = uh_pubsub[0];
        ASSERT_EQ(uhps0 -> get_type(), OpenPGP::Subpacket::Tag2::ISSUER);
        // pubsig/sub16
        {
            const OpenPGP::Subpacket::Tag2::Sub16::Ptr pubsub16 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub16> (uhps0);
            EXPECT_EQ(pubsub16 -> get_keyid(), "\xd5\xd7\xda\x71\xc3\x54\x96\x0e");
        }
    }

    // subkey
    {
        EXPECT_EQ(subkey -> get_time(), gen_time);                                   // 2014-06-22T12:50:48 UTC
        EXPECT_EQ(subkey -> get_pka(), OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN);
        const OpenPGP::PKA::Values mpi = subkey -> get_mpi();
        EXPECT_EQ(OpenPGP::bitsize(mpi[0]), (std::size_t) 2048);                     // 2048-bit
        EXPECT_EQ(OpenPGP::mpitohex(mpi[0]), "d98aac4e3f499e2264aebd71ea0e7d8a8d4690ff73d09125cd197892f1bb59492b8523dc5e4a0b9e0702babf65a71113d96a7ba2ee37cdc2ae8b0b03c67b16c12bd67e6835e4de01cd84baba53fb3d22294252dbb2ba854d1fe25f473b6ac8141392697bc6049d3865d9a00f909971e3b1903758e11b13a4661cf79080beac6d9ddb9113dfa788d2fc38a073b8d2717d0e28721f37dc0f7b6eb9a389f8050fac387ba3dedaf32210995534df5188982d431d0f6d93daa48b10ae7a337571f8bbcea59c9677789eedc2fcf2572f3d2ace9ae12b4817aa08d9541a423d0e60fd657f332c3fe47eef242e56715d25422971b6381a1e6a52bbae574da0077f83a535");
        EXPECT_EQ(OpenPGP::bitsize(mpi[1]), (std::size_t) 17);                       // 17-bit
        EXPECT_EQ(mpi[1], 0x10001);
    }

    // subsig
    {
        EXPECT_EQ(subsig -> get_type(), OpenPGP::Signature_Type::SUBKEY_BINDING_SIGNATURE);
        EXPECT_EQ(subsig -> get_pka(), OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN);
        EXPECT_EQ(subsig -> get_hash(), OpenPGP::Hash::ID::SHA1);
        EXPECT_EQ(subsig -> get_left16(), "\x9a\xeb");
        EXPECT_EQ(OpenPGP::bitsize(subsig -> get_mpi()[0]), (std::size_t) 2047);     // 2047-bit

        // subsig/hashed
        const OpenPGP::Packet::Tag2::Subpackets subsub = subsig -> get_hashed_subpackets();
        ASSERT_EQ(subsub.size(), (OpenPGP::Packet::Tag2::Subpackets::size_type) 2);

        ASSERT_EQ(subsub[0] -> get_type(), OpenPGP::Subpacket::Tag2::SIGNATURE_CREATION_TIME);
        ASSERT_EQ(subsub[1] -> get_type(), OpenPGP::Subpacket::Tag2::KEY_FLAGS);

        // subsig/sub2
        {
            const OpenPGP::Subpacket::Tag2::Sub2::Ptr subsub2 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub2>  (subsub[0]);
            EXPECT_EQ(subsub2 -> get_time(), gen_time);                              // 2014-06-22T12:50:48 UTC
        }

        // subsig/sub27
        {
            const OpenPGP::Subpacket::Tag2::Sub27::Ptr subsub27 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub27> (subsub[1]);
            EXPECT_EQ(subsub27 -> get_flags(), std::string(1, 4 | 8));
        }

        // subsig/unhashed
        const OpenPGP::Packet::Tag2::Subpackets uh_subsub = subsig -> get_unhashed_subpackets();
        ASSERT_EQ(uh_subsub.size(), (OpenPGP::Packet::Tag2::Subpackets::size_type) 1);
        const OpenPGP::Subpacket::Tag2::Sub::Ptr uhss0 = uh_subsub[0];
        ASSERT_EQ(uhss0 -> get_type(), OpenPGP::Subpacket::Tag2::ISSUER);

        // subsig/sub16
        {
            const OpenPGP::Subpacket::Tag2::Sub16::Ptr subsub16 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub16> (uhss0);
            EXPECT_EQ(subsub16 -> get_keyid(), "\xd5\xd7\xda\x71\xc3\x54\x96\x0e");
        }
    }
}

TEST(gpg, private_key){

    OpenPGP::SecretKey pri;
    ASSERT_EQ(read_pgp <OpenPGP::SecretKey> ("Alicepri", pri), true);

    // read private key into OpenPGP::PublicKey::
    {
        OpenPGP::PublicKey pub;
        EXPECT_EQ(read_pgp <OpenPGP::PublicKey> ("Alicepri", pub), false);
    }

    ASSERT_EQ(pri.keyid(), unhexlify("d5d7da71c354960e"));
    ASSERT_EQ(pri.fingerprint(), unhexlify("4b3292e956b577ad703443f4d5d7da71c354960e"));

    const OpenPGP::PGP::Packets packets = pri.get_packets();
    ASSERT_EQ(packets.size(), (OpenPGP::PGP::Packets::size_type) 5);

    ASSERT_EQ(packets[0] -> get_tag(), OpenPGP::Packet::SECRET_KEY);
    ASSERT_EQ(packets[1] -> get_tag(), OpenPGP::Packet::USER_ID);
    ASSERT_EQ(packets[2] -> get_tag(), OpenPGP::Packet::SIGNATURE);
    ASSERT_EQ(packets[3] -> get_tag(), OpenPGP::Packet::SECRET_SUBKEY);
    ASSERT_EQ(packets[4] -> get_tag(), OpenPGP::Packet::SIGNATURE);
    const OpenPGP::Packet::Tag5::Ptr  seckey = std::dynamic_pointer_cast <OpenPGP::Packet::Tag5>  (packets[0]);
    const OpenPGP::Packet::Tag13::Ptr userid = std::dynamic_pointer_cast <OpenPGP::Packet::Tag13> (packets[1]);
    const OpenPGP::Packet::Tag2::Ptr  pubsig = std::dynamic_pointer_cast <OpenPGP::Packet::Tag2>  (packets[2]);
    const OpenPGP::Packet::Tag7::Ptr  subkey = std::dynamic_pointer_cast <OpenPGP::Packet::Tag7>  (packets[3]);
    const OpenPGP::Packet::Tag2::Ptr  subsig = std::dynamic_pointer_cast <OpenPGP::Packet::Tag2>  (packets[4]);

    EXPECT_EQ(seckey -> get_version(), (uint8_t) 4);
    EXPECT_EQ(subkey -> get_version(), (uint8_t) 4);
    EXPECT_EQ(pubsig -> get_version(), (uint8_t) 4);
    EXPECT_EQ(subsig -> get_version(), (uint8_t) 4);

    EXPECT_EQ(seckey -> get_size(), (std::size_t) 958);
    EXPECT_EQ(userid -> get_size(), (std::size_t)  36);
    EXPECT_EQ(pubsig -> get_size(), (std::size_t) 312);
    EXPECT_EQ(subkey -> get_size(), (std::size_t) 958);
    EXPECT_EQ(subsig -> get_size(), (std::size_t) 287);

    const time_t gen_time = get_utc(2014, 6, 22, 12, 50, 48);            // 2014-06-22T12:50:48 UTC

    // seckey
    {
        EXPECT_EQ(seckey -> get_time(), gen_time);                       // 2014-06-22T12:50:48 UTC
        EXPECT_EQ(seckey -> get_pka(), OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN);
        const OpenPGP::PKA::Values mpi = seckey -> get_mpi();
        EXPECT_EQ(OpenPGP::bitsize(mpi[0]), (std::size_t) 2048);         // 2048-bit
        EXPECT_EQ(OpenPGP::mpitohex(mpi[0]), "bc047e94d471f3ccbd525d6a6f8e17f7b1f00527c722c3913ce787fbd0090e3af8be7e59410f63b3983a9507b761045c11510e62f5a8cfbcdc180976a4c225737b8e06d8531f38c6eaa996954d5521a6763231f07c2b43605d052abdf39d6c668ac94bc89f543052d050530c70c48a49a970867c00178f9076dd0e151d254632767b2926e9baa22c6d0c213f1f45de74991396d7e8d10508cf679139410ab311b1279dd3c0d37facca54d523cd14a3df488eb8f592c5a19bcfede67c8170815c588adf39d188197da40492aac5b183c303f6ef23b0b5e48ff73b2d806afb0fb4f16ba32769249d3a7ca0ef0b9b3d57852dc9a979b6d56f3dc170e28dcb2e536d");
        EXPECT_EQ(OpenPGP::bitsize(mpi[1]), (std::size_t) 17);           // 17-bit
        EXPECT_EQ(mpi[1], 0x10001);
        EXPECT_EQ(seckey -> get_sym(), OpenPGP::Sym::ID::CAST5);
        EXPECT_EQ(seckey -> get_IV(), "\x47\xdb\x0a\x37\x11\x76\xb3\x5d");
        const OpenPGP::S2K::S2K::Ptr secs2k = seckey -> get_s2k();
        EXPECT_EQ(secs2k -> get_type(), OpenPGP::S2K::ID::ITERATED_AND_SALTED_S2K);
        EXPECT_EQ(secs2k -> get_hash(), OpenPGP::Hash::ID::SHA1);
        const OpenPGP::S2K::S2K3::Ptr secs2k3 = std::dynamic_pointer_cast <OpenPGP::S2K::S2K3> (secs2k);
        EXPECT_EQ(secs2k3 -> get_count(), (uint8_t) 96);
        const OpenPGP::PKA::Values secmpi = seckey -> decrypt_secret_keys(PASSPHRASE);
        EXPECT_EQ(secmpi.size(), (OpenPGP::PKA::Values::size_type) 4);
        EXPECT_EQ(OpenPGP::mpitohex(secmpi[0]), "03949bbb19be693235e62b7ef33fcd6f5813afb7d8db542c99a3921eed10a3153050c993e30dbe6c454939836d27bb5f2c137323899bccd48fd909efe5b93b60a645daaf6aa3d1b8ee08fed72d56158bd13cb62c73e34ba0ed82f6ba76390eff43ea71f110ae7e814ad3fa5e8007dd5750acc92873aaff320ea56cf0ade4dc7994ac78d9dfc567ead2589f514ac4a95d2a28685d1f593129f7f82fdaca2e4e87b4b223ca3d6c742370bfba2a4954b1c7bcf4290addad26c2a52ea4a5d664a8c32cf729bb1c783fa817ef50c5432a3c1c73ef9d1e08ecf9780d5f3c8667ade01f397270b2919d632cba1ccd4c0861cb8420f4eabe8606115342657a281f1051d1");
        EXPECT_EQ(OpenPGP::mpitohex(secmpi[1]), "d03b3727809678a98fb4f94f9fde836efeaacafefd721ebb83c90dfebcc169a88944859afb2c4154c20d45a155d85bf692be56c1778b0bd94b77fd878d81bbe5584fbb28e716785821b1f4e0a3bffb7bc812c51394dc803d53afa261745092ed3169fcc7e2d125f2595a1555efc5f350be6654b050057839be3fc3ac1719453d");
        EXPECT_EQ(OpenPGP::mpitohex(secmpi[2]), "e7262ff9b96de7b93a9977edebd1b424217c8e1edce2e1ac9e38493ef5e727b4fbbc64312e0a48823fa5e71292d939e724f2c5d32eed544be5e7bc3421b4b6031cd65b1d8531d24e1d44bd282edddb20f58abdd78722a18e4f62fde869381f5e6040e1163e399f7b7b614f17bb51038c23c57b1d87241d97dbc7e4b85e1909f1");
        EXPECT_EQ(OpenPGP::mpitohex(secmpi[3]), "a5b011afc09d933d7f75b58e750bee1f05bf95d7bc354d3989eaa58cbdf85c367536b11dd29e016fe90f419288765e50af6e00a96660169716313f8d4080ce407cbad43a912e23170552d97a0465ab90a0a6b879a85bef0c2bbae100cbfc2927a01a0842fe8c2c6234149b35c05075438f7f4e2a3d5f19f427f423b868c0dad1");
    }

    // userid
    {
        EXPECT_EQ(userid -> raw(), "alice (test key) <alice@example.com>");
    }

    // pubsig (same as test_gpg_public_key)
    {
        EXPECT_EQ(pubsig -> get_type(), OpenPGP::Signature_Type::POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET);
        EXPECT_EQ(pubsig -> get_pka(), OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN);
        EXPECT_EQ(pubsig -> get_hash(), OpenPGP::Hash::ID::SHA1);
        EXPECT_EQ(pubsig -> get_left16(), "\x04\x5e");
        const OpenPGP::PKA::Values mpi = pubsig -> get_mpi();
        ASSERT_EQ(mpi.size(), (OpenPGP::PKA::Values::size_type) 1);
        EXPECT_EQ(OpenPGP::bitsize(mpi[0]), (std::size_t) 2047);         // 2047-bit
        EXPECT_EQ(OpenPGP::mpitohex(mpi[0]), "688a18a258f866cf50f1c938dc15b11298da0bfbd680241f52545af5023722858cdfb579da22e66dae36dff9a817f797192e95b7074bab49381acb837f1216d4e8e3c2de2fb5547a515b5236823bcb4b3bca1a68455fa984c4dc21b1a5af2308aea580c0ae2ca3f5db343beaa559524702d09e40d1923314ef0f15646acec91b9c6d9cba9d9b87fa78626a522ae1520f0aed361df00f8191a9ecb1fb12732e9f6e5e1c4bece397e4dcfbacd41918882c2dfa75b98b54587f0cd61195bdce41b690329a746c6e37b7e2ef9b06206bf280ff93ec0b891929790492a9971acaa9e7e141585ca41800dd462b6f8235c0f1e0b691a5054da8f90295f5949e22fb5e5c");

        // pubsig/hashed
        const OpenPGP::Packet::Tag2::Subpackets pubsub = pubsig -> get_hashed_subpackets();
        ASSERT_EQ(pubsub.size(), (OpenPGP::Packet::Tag2::Subpackets::size_type) 7);
        ASSERT_EQ(pubsub[0] -> get_type(), OpenPGP::Subpacket::Tag2::SIGNATURE_CREATION_TIME);
        ASSERT_EQ(pubsub[1] -> get_type(), OpenPGP::Subpacket::Tag2::KEY_FLAGS);
        ASSERT_EQ(pubsub[2] -> get_type(), OpenPGP::Subpacket::Tag2::PREFERRED_SYMMETRIC_ALGORITHMS);
        ASSERT_EQ(pubsub[3] -> get_type(), OpenPGP::Subpacket::Tag2::PREFERRED_HASH_ALGORITHMS);
        ASSERT_EQ(pubsub[4] -> get_type(), OpenPGP::Subpacket::Tag2::PREFERRED_COMPRESSION_ALGORITHMS);
        ASSERT_EQ(pubsub[5] -> get_type(), OpenPGP::Subpacket::Tag2::FEATURES);
        ASSERT_EQ(pubsub[6] -> get_type(), OpenPGP::Subpacket::Tag2::KEY_SERVER_PREFERENCES);

        // pubsig/sub2
        {
            const OpenPGP::Subpacket::Tag2::Sub2::Ptr pubsub2 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub2>  (pubsub[0]);
            EXPECT_EQ(pubsub2 -> get_time(), gen_time);         // 2014-06-22T12:50:48 UTC
        }

        // pubsig/sub27
        {
            const OpenPGP::Subpacket::Tag2::Sub27::Ptr pubsub27 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub27> (pubsub[1]);
            EXPECT_EQ(pubsub27 -> get_flags(), std::string(1, 1 | 2));
        }

        // pubsig/sub11
        {
            const OpenPGP::Subpacket::Tag2::Sub11::Ptr pubsub11 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub11> (pubsub[2]);
            std::string psa = pubsub11 -> get_psa();
            EXPECT_EQ(psa.size(), (std::string::size_type) 5);
            EXPECT_NE(psa.find(OpenPGP::Sym::ID::AES128),    std::string::npos);
            EXPECT_NE(psa.find(OpenPGP::Sym::ID::AES192),    std::string::npos);
            EXPECT_NE(psa.find(OpenPGP::Sym::ID::AES256),    std::string::npos);
            EXPECT_NE(psa.find(OpenPGP::Sym::ID::CAST5),     std::string::npos);
            EXPECT_NE(psa.find(OpenPGP::Sym::ID::TRIPLEDES), std::string::npos);
        }

        // pubsig/sub21
        {
            const OpenPGP::Subpacket::Tag2::Sub21::Ptr pubsub21 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub21> (pubsub[3]);
            std::string pha = pubsub21 -> get_pha();
            EXPECT_EQ(pha.size(), (std::string::size_type) 5);
            EXPECT_NE(pha.find(OpenPGP::Hash::ID::SHA256), std::string::npos);
            EXPECT_NE(pha.find(OpenPGP::Hash::ID::SHA1),   std::string::npos);
            EXPECT_NE(pha.find(OpenPGP::Hash::ID::SHA384), std::string::npos);
            EXPECT_NE(pha.find(OpenPGP::Hash::ID::SHA512), std::string::npos);
            EXPECT_NE(pha.find(OpenPGP::Hash::ID::SHA224), std::string::npos);
        }

        // pubsig/sub22
        {
            const OpenPGP::Subpacket::Tag2::Sub22::Ptr pubsub22 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub22> (pubsub[4]);
            std::string pca = pubsub22 -> get_pca();
            EXPECT_EQ(pca.size(), (std::string::size_type) 3);
            EXPECT_NE(pca.find(OpenPGP::Compression::ID::ZLIB),  std::string::npos);
            EXPECT_NE(pca.find(OpenPGP::Compression::ID::BZIP2), std::string::npos);
            EXPECT_NE(pca.find(OpenPGP::Compression::ID::ZIP),   std::string::npos);
        }

        // pubsig/sub30
        {
            const OpenPGP::Subpacket::Tag2::Sub30::Ptr pubsub30 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub30> (pubsub[5]);
            EXPECT_EQ(pubsub30 -> get_flags().size(), (std::string::size_type) 1);
            EXPECT_EQ(pubsub30 -> get_flags()[0], OpenPGP::Subpacket::Tag2::Features_Flags::MODIFICATION_DETECTION);
        }

        // pubsig/sub23
        {
            const OpenPGP::Subpacket::Tag2::Sub23::Ptr pubsub23 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub23> (pubsub[6]);
            EXPECT_EQ(pubsub23 -> get_flags().size(), (std::string::size_type) 1);
            EXPECT_EQ(static_cast <uint8_t> (pubsub23 -> get_flags()[0]), OpenPGP::Subpacket::Tag2::Key_Server_Preferences::NO_MODIFY);
        }

        // pubsig/unhashed
        const OpenPGP::Packet::Tag2::Subpackets uh_pubsub = pubsig -> get_unhashed_subpackets();
        ASSERT_EQ(uh_pubsub.size(), (OpenPGP::Packet::Tag2::Subpackets::size_type) 1);
        const OpenPGP::Subpacket::Tag2::Sub::Ptr uhps0 = uh_pubsub[0];
        ASSERT_EQ(uhps0 -> get_type(), OpenPGP::Subpacket::Tag2::ISSUER);

        // pubsig/sub16
        {
            const OpenPGP::Subpacket::Tag2::Sub16::Ptr pubsub16 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub16> (uhps0);
            EXPECT_EQ(pubsub16 -> get_keyid(), "\xd5\xd7\xda\x71\xc3\x54\x96\x0e");
        }
    }

    // subkey
    {
        EXPECT_EQ(subkey -> get_time(), gen_time); // 2014-06-22T12:50:48 UTC
        EXPECT_EQ(subkey -> get_pka(), OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN);
        const OpenPGP::PKA::Values mpi = subkey -> get_mpi();
        EXPECT_EQ(OpenPGP::bitsize(mpi[0]), (std::size_t) 2048); // 2048-bit
        EXPECT_EQ(OpenPGP::mpitohex(mpi[0]), "d98aac4e3f499e2264aebd71ea0e7d8a8d4690ff73d09125cd197892f1bb59492b8523dc5e4a0b9e0702babf65a71113d96a7ba2ee37cdc2ae8b0b03c67b16c12bd67e6835e4de01cd84baba53fb3d22294252dbb2ba854d1fe25f473b6ac8141392697bc6049d3865d9a00f909971e3b1903758e11b13a4661cf79080beac6d9ddb9113dfa788d2fc38a073b8d2717d0e28721f37dc0f7b6eb9a389f8050fac387ba3dedaf32210995534df5188982d431d0f6d93daa48b10ae7a337571f8bbcea59c9677789eedc2fcf2572f3d2ace9ae12b4817aa08d9541a423d0e60fd657f332c3fe47eef242e56715d25422971b6381a1e6a52bbae574da0077f83a535");
        EXPECT_EQ(OpenPGP::bitsize(mpi[1]), (std::size_t) 17);   // 17-bit
        EXPECT_EQ(mpi[1], 0x10001);
        EXPECT_EQ(subkey -> get_sym(), OpenPGP::Sym::ID::CAST5);
        EXPECT_EQ(subkey -> get_IV(), "\x22\x01\xe4\x2a\xc6\x81\x4d\x35");
        const OpenPGP::S2K::S2K::Ptr subs2k = subkey -> get_s2k();
        EXPECT_EQ(subs2k -> get_type(), OpenPGP::S2K::ID::ITERATED_AND_SALTED_S2K);
        EXPECT_EQ(subs2k -> get_hash(), OpenPGP::Hash::ID::SHA1);
        const OpenPGP::S2K::S2K3::Ptr subs2k3 = std::dynamic_pointer_cast <OpenPGP::S2K::S2K3> (subs2k);
        EXPECT_EQ(subs2k3 -> get_count(), (uint8_t) 96);
        const OpenPGP::PKA::Values secmpi = subkey -> decrypt_secret_keys(PASSPHRASE);
        EXPECT_EQ(secmpi.size(), (OpenPGP::PKA::Values::size_type) 4);
        EXPECT_EQ(OpenPGP::mpitohex(secmpi[0]), "6275226e19b3ba880b7490d6855e0090dc47136a22a343864dd118e2bcd893dd0b7eeb4f9a373e11cc4f7e7110d36fe5c171b1ba78c1b5f5466534db851201a6f52dd3b15baf1591d05021e92208644f594824d33d8db0b64ad77c52f37fed4534e47fac5edf88bed54e0d64ee079ce5b66034c49bc152ff059e57a7c5b546b9526a98fa7d2371d8843887c7708a5a5db82f3520cb7d784602b145e4c3de287fc2dd50a9b9c99d34176852e1024cf1eac2d9039b5a690991ee2f1b178c308587f62801955d3254530203b039823aec6d50bd40d791711fff815c76cd99164725cd43f4c2134c1053f63281d4a6d210809f6b686a3db45d66ebd85ac16883e413");
        EXPECT_EQ(OpenPGP::mpitohex(secmpi[1]), "ebc63b9c2c5002d77f3f3261ce3ebdd4710827b180f0a2b5b847c2e5e6365903fc8ae73078666737850c0575d1ef558b0d77e3039f1e4cef6a97e90ccc70bec4459f4140725d98f2d275f81da1326b34cf1e0b0b69466e878e2c98823732ea5baa0cff7d687bf44590a0bab69f6d7182dcfb8ec20197fe9533730ce0549f991b");
        EXPECT_EQ(OpenPGP::mpitohex(secmpi[2]), "ec3409ddb6f104384a7f4788ba73164d8420bdbc240d815c6e615603955ca128a388c21c0c19fe42be806922c2708d37efefd57a52f1fb777cfad002f2ba4f6c4c7119734340f13639b02a5c66d9b98048388ab3e97fca8f47fb07d360ed629762c045929f4f60c37c34a52ae75a12be68cb9644d7867de03029c3dccc736fef");
        EXPECT_EQ(OpenPGP::mpitohex(secmpi[3]), "0547d7351f3047b5d4728cfed246eef218e4d0840d5f5edb9faf723da93bbb914e806a8ea569889eada1a37a6dd69da1c7f6f2e21d8fc6622dc759adb97a3e4003fcd7a499bcecebf9b7f4be958c3486501810ce321b2c343d1d19aae7f6b6454b5a7a5c551986f49e904b63a6f7cc32ccafa78bb7a7696d627ba67489cdcc89");
    }

    // subsig (same as public_key)
    {
        EXPECT_EQ(subsig -> get_type(), OpenPGP::Signature_Type::SUBKEY_BINDING_SIGNATURE);
        EXPECT_EQ(subsig -> get_pka(), OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN);
        EXPECT_EQ(subsig -> get_hash(), OpenPGP::Hash::ID::SHA1);
        EXPECT_EQ(subsig -> get_left16(), "\x9a\xeb");
        EXPECT_EQ(OpenPGP::bitsize(subsig -> get_mpi()[0]), (std::size_t) 2047); // 2047-bit

        // subsig/hashed
        const OpenPGP::Packet::Tag2::Subpackets subsub = subsig -> get_hashed_subpackets();
        ASSERT_EQ(subsub.size(), (OpenPGP::Packet::Tag2::Subpackets::size_type) 2);
        ASSERT_EQ(subsub[0] -> get_type(), (uint8_t)  2);
        ASSERT_EQ(subsub[1] -> get_type(), (uint8_t) 27);

        // subsig/sub2
        {
            const OpenPGP::Subpacket::Tag2::Sub2::Ptr subsub2  = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub2> (subsub[0]);
            EXPECT_EQ(subsub2 -> get_time(), gen_time); // 2014-06-22T12:50:48 UTC
        }

        // subsig/sub27
        {
            const OpenPGP::Subpacket::Tag2::Sub27::Ptr subsub27 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub27> (subsub[1]);
            EXPECT_EQ(subsub27 -> get_flags(), std::string(1, 4 | 8));
        }

        // subsig/unhashed
        const OpenPGP::Packet::Tag2::Subpackets uh_subsub = subsig -> get_unhashed_subpackets();
        ASSERT_EQ(uh_subsub.size(), (OpenPGP::Packet::Tag2::Subpackets::size_type) 1);
        const OpenPGP::Subpacket::Tag2::Sub::Ptr uhss0 = uh_subsub[0];
        ASSERT_EQ(uhss0 -> get_type(), OpenPGP::Subpacket::Tag2::ISSUER);
        // subsig/sub16
        {
            const OpenPGP::Subpacket::Tag2::Sub16::Ptr subsub16 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub16> (uhss0);
            EXPECT_EQ(subsub16 -> get_keyid(), "\xd5\xd7\xda\x71\xc3\x54\x96\x0e");
        }
    }
}

TEST(gpg, revoke){

    OpenPGP::SecretKey pri;
    ASSERT_EQ(read_pgp <OpenPGP::SecretKey> ("Alicepri", pri), true);

    OpenPGP::RevocationCertificate rev;
    ASSERT_EQ(read_pgp <OpenPGP::RevocationCertificate> ("revoke", rev), true);

    const OpenPGP::PGP::Packets packets = rev.get_packets();
    ASSERT_EQ(packets.size(), (OpenPGP::PGP::Packets::size_type) 1);

    ASSERT_EQ(packets[0] -> get_tag(), (uint8_t) 2);
    const OpenPGP::Packet::Tag2::Ptr revsig = std::dynamic_pointer_cast <OpenPGP::Packet::Tag2> (packets[0]);

    EXPECT_EQ(revsig -> get_version(), (uint8_t)    4);
    EXPECT_EQ(revsig -> get_size(), (std::size_t) 287);

    EXPECT_EQ(revsig -> get_type(), OpenPGP::Signature_Type::KEY_REVOCATION_SIGNATURE);
    EXPECT_EQ(revsig -> get_pka(), OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN);
    EXPECT_EQ(revsig -> get_hash(), OpenPGP::Hash::ID::SHA1);
    EXPECT_EQ(revsig -> get_left16(), "\xcf\xb9");

    const OpenPGP::PKA::Values mpi = revsig -> get_mpi();
    ASSERT_EQ(mpi.size(), (OpenPGP::PKA::Values::size_type) 1);
    EXPECT_EQ(OpenPGP::bitsize(mpi[0]), (std::size_t) 2045);
    EXPECT_EQ(OpenPGP::mpitohex(mpi[0]), "133edac0fa9b187e05f8ce8dade82f31d3a266190f911b79aed0974952601b3effeed8a1a1dca9f742292a308be8cac43ff2c801ef901c06c6c6a520736dfc4b02c8f92af7a99a03f89d3d62df9844cb6271e409200a7fb6d2e29fe3e72be5305004a39765bf7f02be6dcde47e44131e5529d397592432a74decc6db6cd627848f1535a6166103e6a17f99256fead668fdeb37a72c3f0bc0c4795db324da138d38c37011d5b071ecce77fb84da464eaa6a75b2e1ab6ffa6653b0539149e5f92cfb0389d843f26cabcc41f0d623966734b2a7fa110430b29f1a7854ae5affbf9e228bbb440152242542585c7a38b95a541a8d9afccffd6c227b0a11bcd60b2bc7");

    // hashed
    {
        const OpenPGP::Packet::Tag2::Subpackets hashed = revsig -> get_hashed_subpackets();
        ASSERT_EQ(hashed.size(), (std::size_t) 2);
        ASSERT_EQ(hashed[0] -> get_type(), OpenPGP::Subpacket::Tag2::SIGNATURE_CREATION_TIME);
        ASSERT_EQ(hashed[1] -> get_type(), OpenPGP::Subpacket::Tag2::REASON_FOR_REVOCATION);

        // sub2
        {
            const OpenPGP::Subpacket::Tag2::Sub2::Ptr sub2 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub2> (hashed[0]);
            EXPECT_EQ(sub2 -> get_time(), get_utc(2014, 6, 22, 13, 03, 49));
        }

        // sub29
        {
            const OpenPGP::Subpacket::Tag2::Sub29::Ptr sub29 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub29> (hashed[1]);
            EXPECT_EQ(sub29 -> get_code(), OpenPGP::Subpacket::Tag2::Revoke::KEY_IS_NO_LONGER_USED);
            EXPECT_EQ(sub29 -> get_reason(), ""); // (empty string)
        }
    }
    // unhashed
    {
        const OpenPGP::Packet::Tag2::Subpackets unhashed = revsig -> get_unhashed_subpackets();
        ASSERT_EQ(unhashed.size(), (OpenPGP::Packet::Tag2::Subpackets::size_type) 1);

        const OpenPGP::Subpacket::Tag2::Sub::Ptr s0 = unhashed[0];
        ASSERT_EQ(s0 -> get_type(), OpenPGP::Subpacket::Tag2::ISSUER);

        const OpenPGP::Subpacket::Tag2::Sub16::Ptr sub16 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub16> (s0);
        EXPECT_EQ(sub16 -> get_keyid(), "\xd5\xd7\xda\x71\xc3\x54\x96\x0e");
    }

    EXPECT_EQ(OpenPGP::Verify::revoke(pri, rev), true);
}

TEST(gpg, decrypt_pka_mdc){

    OpenPGP::SecretKey pri;
    ASSERT_EQ(read_pgp <OpenPGP::SecretKey> ("Alicepri", pri), true);

    OpenPGP::Message gpg_encrypted;
    ASSERT_EQ(read_pgp <OpenPGP::Message> ("pkaencrypted", gpg_encrypted), true);

    // make sure data was read correctly
    const OpenPGP::PGP::Packets packets = gpg_encrypted.get_packets();
    ASSERT_EQ(packets.size(), (OpenPGP::PGP::Packets::size_type) 2);

    // tag 1
    {
        ASSERT_EQ(packets[0] -> get_tag(), OpenPGP::Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY);
        const OpenPGP::Packet::Tag1::Ptr tag1 = std::dynamic_pointer_cast <OpenPGP::Packet::Tag1> (packets[0]);
        EXPECT_EQ(tag1 -> get_version(), 3);
        EXPECT_EQ(tag1 -> get_keyid(), "\x9f\x0f\xf4\x0f\xd2\x70\x61\xe1");
        EXPECT_EQ(tag1 -> get_pka(), OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN);

        const OpenPGP::PKA::Values mpi = tag1 -> get_mpi();
        ASSERT_EQ(mpi.size(), (OpenPGP::PKA::Values::size_type) 1);
        EXPECT_EQ(OpenPGP::bitsize(mpi[0]), (std::size_t) 2047);
        EXPECT_EQ(OpenPGP::mpitohex(mpi[0]), "53031ee2f4be3ea2808d4fc7258f75a652af233ad5be0cd910e615ed266691e8ac584b3960b09c6c5d65c8c68d4caa46c5fe172cba7042aaf23da1a7f7ca61aad28015f88935ecd91f8501f3f9f85302a507c862aad2d9b7ed975bd5704aaeb57a0eebc2c393315dbe6e27b0e3f3347ccc677f1952dfa9ad2bbc6980386b9086729687113cac9842f6bf802aeb376932770844f8e96bea683be14557f57ba6b735f1f9c5f2e5a56acbf810f7aacc9d9657be659f707aec6a9a6aa3616a6b2e10a8dc94cccbca39cf80e1dc3205803a0ebe6614871be4a52117b0a39b0bc67919c3a2dbcfbb6ca0b21f39cd8f5374f3adf2adc97f7697f663ffa985c47e7de16f");
    }

    // tag 18
    {
        ASSERT_EQ(packets[1] -> get_tag(), OpenPGP::Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA);

        const OpenPGP::Packet::Tag18::Ptr tag18 = std::dynamic_pointer_cast <OpenPGP::Packet::Tag18> (packets[1]);

        EXPECT_EQ(tag18 -> get_version(), 1);
        EXPECT_EQ(hexlify(tag18 -> get_protected_data()), "07436d8ab250d1e811651aac4322dc46bd9cad106e57c6d8ecfb47059d0730e91a064c7d423813d37e2607b09e17e1852dfc96c0d7490bcaba4092b26e989412ccd11030ab11be2460760a46d70de227a807a51d9b926bc6553bd8eb8c68f20777ef32f6712cab313e205156");
    }

    // decrypt data
    const OpenPGP::Message decrypted = OpenPGP::Decrypt::pka(pri, PASSPHRASE, gpg_encrypted);
    std::string message = "";
    for(OpenPGP::Packet::Tag::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == OpenPGP::Packet::LITERAL_DATA){
            message += std::dynamic_pointer_cast <OpenPGP::Packet::Tag11> (p) -> out(false);
        }
    }
    EXPECT_EQ(message, MESSAGE);
}

TEST(gpg, decrypt_pka_no_mdc){

    OpenPGP::SecretKey pri;
    ASSERT_EQ(read_pgp <OpenPGP::SecretKey> ("Alicepri", pri), true);
    ASSERT_EQ(pri.meaningful(), true);

    OpenPGP::Message gpg_encrypted;
    ASSERT_EQ(read_pgp <OpenPGP::Message> ("pkaencryptednomdc", gpg_encrypted), true);
    ASSERT_EQ(gpg_encrypted.meaningful(), true);

    // make sure data was read correctly
    const OpenPGP::PGP::Packets packets = gpg_encrypted.get_packets();
    ASSERT_EQ(packets.size(), (OpenPGP::PGP::Packets::size_type) 2);

    // tag 1
    {
        ASSERT_EQ(packets[0] -> get_tag(), OpenPGP::Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY);
        const OpenPGP::Packet::Tag1::Ptr tag1 = std::dynamic_pointer_cast <OpenPGP::Packet::Tag1> (packets[0]);
        EXPECT_EQ(tag1 -> get_version(), 3);
        EXPECT_EQ(tag1 -> get_keyid(), "\x9f\x0f\xf4\x0f\xd2\x70\x61\xe1");
        EXPECT_EQ(tag1 -> get_pka(), OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN);

        const OpenPGP::PKA::Values mpi = tag1 -> get_mpi();
        ASSERT_EQ(mpi.size(), (OpenPGP::PKA::Values::size_type) 1);
        EXPECT_EQ(OpenPGP::bitsize(mpi[0]), (std::size_t) 2046);
        EXPECT_EQ(OpenPGP::mpitohex(mpi[0]), "242e7b9b10c71670ed1dcd3100d35fc30f27958ba40a4a825c01ae9ebcbecd59d92dbe757013b13553620770331ed2c3fbb23d6920d91d606a6f597309cac772589b400d31a6425cc86b2b43aefe34e58cb306eab42f1943813103d10b4ecdac3ef51c9112692e2719b9a85c64c2907bf67f6a5c38c1254796649ed19823658e56dcbb2192d13f201cd1cb9114d11ba2766989429425e664f97936086feab11bcae4ca990f3e3ae42051210d0ddcb777f1c7317a5a733b886d3b016da20e024f633c19d8fa71c4a6f4ea240d7836983f5c8b0ea6664766aef8822fb39f0019c96859264e475c6eeef4c6cabb310926a0ef39fec49d9b3b30d5c72f7a10ebf0a5");
    }

    // tag 9
    {
        ASSERT_EQ(packets[1] -> get_tag(), OpenPGP::Packet::SYMMETRICALLY_ENCRYPTED_DATA);

        const OpenPGP::Packet::Tag9::Ptr tag9 = std::dynamic_pointer_cast <OpenPGP::Packet::Tag9> (packets[1]);
        EXPECT_EQ(hexlify(tag9 -> get_encrypted_data()), "57f10c501129c02e0c1a35886c498a9eca38dbe6e405c978f326d375b0e96e72f7118fb89ea3317567e5308a965c730abc3756632b405904330cf4b2b37ec572242a5d628da4796b1efc327206f45f");
    }

    // decrypt data
    const OpenPGP::Message decrypted = OpenPGP::Decrypt::pka(pri, PASSPHRASE, gpg_encrypted);
    std::string message = "";
    for(OpenPGP::Packet::Tag::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == OpenPGP::Packet::LITERAL_DATA){
            message += std::dynamic_pointer_cast <OpenPGP::Packet::Tag11> (p) -> out(false);
        }
    }
    EXPECT_EQ(message, MESSAGE);
}

TEST(gpg, decrypt_symmetric_mdc){

    OpenPGP::Message gpg_encrypted;
    ASSERT_EQ(read_pgp <OpenPGP::Message> ("symencrypted", gpg_encrypted), true);

    // make sure data was read correctly
    const OpenPGP::PGP::Packets packets = gpg_encrypted.get_packets();
    ASSERT_EQ(packets.size(), (OpenPGP::PGP::Packets::size_type) 2);

    // tag 3
    {
        ASSERT_EQ(packets[0] -> get_tag(), OpenPGP::Packet::SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY);
        const OpenPGP::Packet::Tag3::Ptr tag3 = std::dynamic_pointer_cast <OpenPGP::Packet::Tag3> (packets[0]);
        EXPECT_EQ(tag3 -> get_version(), 4);
        EXPECT_EQ(tag3 -> get_sym(), OpenPGP::Sym::ID::AES128);

        const OpenPGP::S2K::S2K::Ptr s2k = tag3 -> get_s2k();
        EXPECT_NE(s2k, nullptr);
        ASSERT_EQ(s2k -> get_type(), OpenPGP::S2K::ID::ITERATED_AND_SALTED_S2K);
        EXPECT_EQ(s2k -> get_hash(), OpenPGP::Hash::ID::SHA1);
        const OpenPGP::S2K::S2K3::Ptr s2k3 = std::dynamic_pointer_cast <OpenPGP::S2K::S2K3> (s2k);
        EXPECT_EQ(s2k3 -> get_salt(), "\x8e\x64\x8b\xe1\xaa\x16\x46\xca");
        EXPECT_EQ(s2k3 -> get_count(), 96);
    }

    // tag 18
    {
        ASSERT_EQ(packets[1] -> get_tag(), OpenPGP::Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA);

        const OpenPGP::Packet::Tag18::Ptr tag18 = std::dynamic_pointer_cast <OpenPGP::Packet::Tag18> (packets[1]);
        EXPECT_EQ(tag18 -> get_version(), 1);
        EXPECT_EQ(hexlify(tag18 -> get_protected_data()), "1d441bb46bd8c2dbabc6e6b2bb214d08cd6d14a86a83b220f118664c0c0d23252b66e1ed0b41146f17007358c57ee846d77fc839784950d0a69085d50393cedec1fab7521ff758d2183a5c5770a91d9f3ea7a50de1d0e4d008846fa0ae23a3");
    }

    // decrypt data
    const OpenPGP::Message decrypted = OpenPGP::Decrypt::sym(gpg_encrypted, PASSPHRASE);
    std::string message = "";
    for(OpenPGP::Packet::Tag::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == OpenPGP::Packet::LITERAL_DATA){
            message += std::dynamic_pointer_cast <OpenPGP::Packet::Tag11> (p) -> out(false);
        }
    }
    EXPECT_EQ(message, MESSAGE);
}

TEST(gpg, decrypt_symmetric_no_mdc){

    OpenPGP::Message gpg_encrypted;
    ASSERT_EQ(read_pgp <OpenPGP::Message> ("symencryptednomdc", gpg_encrypted), true);

    // make sure data was read correctly
    const OpenPGP::PGP::Packets packets = gpg_encrypted.get_packets();
    ASSERT_EQ(packets.size(), (OpenPGP::PGP::Packets::size_type) 2);

    // tag 3
    {
        ASSERT_EQ(packets[0] -> get_tag(), OpenPGP::Packet::SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY);
        const OpenPGP::Packet::Tag3::Ptr tag3 = std::dynamic_pointer_cast <OpenPGP::Packet::Tag3> (packets[0]);
        EXPECT_EQ(tag3 -> get_version(), 4);
        EXPECT_EQ(tag3 -> get_sym(), OpenPGP::Sym::ID::AES128);

        const OpenPGP::S2K::S2K::Ptr s2k = tag3 -> get_s2k();
        EXPECT_NE(s2k, nullptr);
        ASSERT_EQ(s2k -> get_type(), OpenPGP::S2K::ID::ITERATED_AND_SALTED_S2K);
        EXPECT_EQ(s2k -> get_hash(), OpenPGP::Hash::ID::SHA1);
        const OpenPGP::S2K::S2K3::Ptr s2k3 = std::dynamic_pointer_cast <OpenPGP::S2K::S2K3> (s2k);
        EXPECT_EQ(s2k3 -> get_salt(), "\x56\x4c\xe8\xd2\x70\xc6\x20\xae");
        EXPECT_EQ(s2k3 -> get_count(), 96);
    }

    // tag 9
    {
        ASSERT_EQ(packets[1] -> get_tag(), OpenPGP::Packet::SYMMETRICALLY_ENCRYPTED_DATA);

        const OpenPGP::Packet::Tag9::Ptr tag9 = std::dynamic_pointer_cast <OpenPGP::Packet::Tag9> (packets[1]);
        EXPECT_EQ(hexlify(tag9 -> get_encrypted_data()), "7d7cdb8dfb36cbc1dee049f412da8bcef90c936b58eee3c74b555b9dc961b08759543cf3ca2ccedc5bd45c09c05c646d083c2faa0fcf0ebe7c036bb6263442a78a8ad96b4dcbd58c12");
    }

    // decrypt data
    const OpenPGP::Message decrypted = OpenPGP::Decrypt::sym(gpg_encrypted, PASSPHRASE);
    std::string message = "";
    for(OpenPGP::Packet::Tag::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == OpenPGP::Packet::LITERAL_DATA){
            message += std::dynamic_pointer_cast <OpenPGP::Packet::Tag11> (p) -> out(false);
        }
    }
    EXPECT_EQ(message, MESSAGE);
}

TEST(gpg, decrypt_verify){

    OpenPGP::SecretKey pri;
    ASSERT_EQ(read_pgp <OpenPGP::SecretKey> ("Alicepri", pri), true);

    OpenPGP::Message gpg_encrypted;
    ASSERT_EQ(read_pgp <OpenPGP::Message> ("encryptsign", gpg_encrypted), true);

    // make sure data was read correctly
    OpenPGP::PGP::Packets packets = gpg_encrypted.get_packets();
    ASSERT_EQ(packets.size(), (OpenPGP::PGP::Packets::size_type) 2);

    // tag 1
    {
        ASSERT_EQ(packets[0] -> get_tag(), OpenPGP::Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY);

        const OpenPGP::Packet::Tag1::Ptr tag1 = std::dynamic_pointer_cast <OpenPGP::Packet::Tag1> (packets[0]);
        EXPECT_EQ(tag1 -> get_version(), 3);
        EXPECT_EQ(tag1 -> get_keyid(), "\x9f\x0f\xf4\x0f\xd2\x70\x61\xe1");
        EXPECT_EQ(tag1 -> get_pka(), OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN);

        const OpenPGP::PKA::Values mpi = tag1 -> get_mpi();
        ASSERT_EQ(mpi.size(), (OpenPGP::PKA::Values::size_type) 1);
        EXPECT_EQ(OpenPGP::bitsize(mpi[0]), (std::size_t) 2047);
        EXPECT_EQ(OpenPGP::mpitohex(mpi[0]), "55ae703b583cfbe6ddac7cb001dd87cfbe3b905d9b333146d802b83e287e67edcaece84582e9e9d8ef87297a80be3da78a71413c4c52b24ba9297f4c42624a02deb20a7ba04f169af3151df18f54641cc20e6b5da114b731b0089e8e8095468cc37a8e88fb461e33d090b4193a406a10063e9be6228a7c210c9054f36da89228a797d49489f66bbce46c8735f7ebec3d6e163983d501dc6ee4039938ccb2435278a48596f719c0cf0767c64cc5424c5f19d20a320be84d0daf873c1ec98a2c14c6debd48613d2d8d65775fac2af27242d73e3ab92156de2616116b7e94d5b4b529a6a48b944e5c7772f47b15233ece35c96635b2833e4dfd7de79d244be3bbb6");
    }

    // tag 18
    {
        ASSERT_EQ(packets[1] -> get_tag(), OpenPGP::Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA);

        const OpenPGP::Packet::Tag18::Ptr tag18 = std::dynamic_pointer_cast <OpenPGP::Packet::Tag18> (packets[1]);
        EXPECT_EQ(tag18 -> get_version(), 1);
        EXPECT_EQ(hexlify(tag18 -> get_protected_data()), "9acbf7dad16cd8f4b120a69afb656aa36071323b5194bfe4ecbfbfa98a08fc554ac5341f80f43ba138b1e1796461263c7f61953be3f28e82346296059bb73de9f7bc705c884b423fc1769e58cd957b4b900bc7dac5e354e031af71c6eb2d5fd5efe54b5c61622cd4b42c7bd958387f18c54d766aa7bd0f74848284c596efe3a7f1239b830d09d6b6edb64dca6c38ff946babc1aea7925bb01d227a3abae75b22790b9f3e13cce84e7b7063dc3eb23bce33b45d82686498514a25b345da130c71aa410ded4b41aa4611d5e123b00aef99d9dd2d183660d9f1c114da7a9d2962764f0ae84477109e3d934cd67b114af8b4762402608080c33fd02dd36f8ff521672492ad0fc632f2a353f875a3ccdf983c144ed9c683b688c6bd88dba582a3094dd19f06aca8b1d7aeea4fb4a8265f56478c7743bee2eac6fac21fa08f043e079983e93759f25aa0d1427986528cb4d0d30e7f404f4abadfe3c6e55e432d2e1d8015e6a10eb4274dd221d1a3c0c39b8956c2c713d6597172d75f10e2f7aebdca8e67bea086a4e92745b4411b712b12a39bf655fe714772");
    }

    // decrypt data
    const OpenPGP::Message decrypted = OpenPGP::Decrypt::pka(pri, PASSPHRASE, gpg_encrypted);
    std::string message = "";
    for(OpenPGP::Packet::Tag::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == OpenPGP::Packet::LITERAL_DATA){
            message += std::dynamic_pointer_cast <OpenPGP::Packet::Tag11> (p) -> out(false);
        }
    }
    EXPECT_EQ(message, MESSAGE);

    EXPECT_EQ(decrypted.get_comp(), OpenPGP::Compression::ID::ZLIB);

    packets = decrypted.get_packets();
    ASSERT_EQ(packets.size(), (OpenPGP::PGP::Packets::size_type) 3);

    const uint32_t gen_time = get_utc(2017, 4, 14, 19, 37, 32);   // 2017-04-14T19:37:32 UTC

    // tag 4
    {
        ASSERT_EQ(packets[0] -> get_tag(), OpenPGP::Packet::ONE_PASS_SIGNATURE);
        const OpenPGP::Packet::Tag4::Ptr tag4 = std::dynamic_pointer_cast <OpenPGP::Packet::Tag4> (packets[0]);
        EXPECT_EQ(tag4 -> get_version(), 3);
        EXPECT_EQ(tag4 -> get_type(), OpenPGP::Signature_Type::SIGNATURE_OF_A_BINARY_DOCUMENT);
        EXPECT_EQ(tag4 -> get_pka(), OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN);
        EXPECT_EQ(tag4 -> get_keyid(), "\xd5\xd7\xda\x71\xc3\x54\x96\x0e");
        EXPECT_EQ(tag4 -> get_nested(), 1);
    }

    // tag 11
    {
        ASSERT_EQ(packets[1] -> get_tag(), OpenPGP::Packet::LITERAL_DATA);
        const OpenPGP::Packet::Tag11::Ptr tag11 = std::dynamic_pointer_cast <OpenPGP::Packet::Tag11> (packets[1]);
        EXPECT_EQ(tag11 -> get_format(), OpenPGP::Packet::Literal::BINARY);
        EXPECT_EQ(tag11 -> get_filename(), "msg");
        EXPECT_EQ(tag11 -> get_time(), gen_time);
        EXPECT_EQ(tag11 -> get_literal(), MESSAGE);
    }

    // tag2
    {
        ASSERT_EQ(packets[2] -> get_tag(), OpenPGP::Packet::SIGNATURE);
        const OpenPGP::Packet::Tag2::Ptr tag2 = std::dynamic_pointer_cast <OpenPGP::Packet::Tag2> (packets[2]);
        EXPECT_EQ(tag2 -> get_version(), 4);
        EXPECT_EQ(tag2 -> get_type(), OpenPGP::Signature_Type::SIGNATURE_OF_A_BINARY_DOCUMENT);
        EXPECT_EQ(tag2 -> get_hash(), OpenPGP::Hash::ID::SHA256);

        // hashed
        const OpenPGP::Packet::Tag2::Subpackets hashed = tag2 -> get_hashed_subpackets();
        ASSERT_EQ(hashed.size(), (OpenPGP::Packet::Tag2::Subpackets::size_type) 1);
        ASSERT_EQ(hashed[0] -> get_type(), OpenPGP::Subpacket::Tag2::SIGNATURE_CREATION_TIME);

        // sub2
        {
            const OpenPGP::Subpacket::Tag2::Sub2::Ptr tag2sub2 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub2> (hashed[0]);
            EXPECT_EQ(tag2sub2 -> get_time(), gen_time);
        }

        // unhashed
        const OpenPGP::Packet::Tag2::Subpackets unhashed = tag2 -> get_unhashed_subpackets();
        ASSERT_EQ(unhashed.size(), (OpenPGP::Packet::Tag2::Subpackets::size_type) 1);
        ASSERT_EQ(unhashed[0] -> get_type(), OpenPGP::Subpacket::Tag2::ISSUER);

        // sub16
        {
            const OpenPGP::Subpacket::Tag2::Sub16::Ptr tag2sub16 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub16> (unhashed[0]);
            EXPECT_EQ(tag2sub16 -> get_keyid(), "\xd5\xd7\xda\x71\xc3\x54\x96\x0e");
        }

        EXPECT_EQ(tag2 -> get_left16(), "\xfc\xb0");

        const OpenPGP::PKA::Values mpi = tag2 -> get_mpi();
        ASSERT_EQ(mpi.size(), (OpenPGP::PKA::Values::size_type) 1);
        EXPECT_EQ(OpenPGP::mpitohex(mpi[0]), "193724362f327439896ac33b0bd2bcf9c19cf04a31d9648fb07fd202dbcf25020f21141298c4ca17f6be0173747d2b50c873975087674d84783d154de8d04de5df0be1751b85fc72cdbbc161486895d19b1cc6b2b2c95b1fa311b5e9c754a55c31ab7ef76c8b5390da3a9769d23cad70bdebc9c70ba8c4c7cff4f707f5e352aa4ea5f00cdcde3df5e8ba1e32af00c78cdd3a81051dc65b8456cd5d6fe4f56c6ca8710b194491d98f8dc4577a55785b3a1d64db15ea14818de5efbc7ef53cfe9749e09df019c9882b4462f7faf6b037612bfede6f07e7d67c109b49d504e32b9bcfac4bf8cf5da2baebf925f5c7d6d4990c84e107ec72c3d9e5782cff052d65c3");
    }

    EXPECT_EQ(OpenPGP::Verify::binary(pri, decrypted), true);
}

TEST(gpg, verify_detached){

    OpenPGP::SecretKey pri;
    ASSERT_EQ(read_pgp <OpenPGP::SecretKey> ("Alicepri", pri), true);

    OpenPGP::DetachedSignature sig;
    ASSERT_EQ(read_pgp <OpenPGP::DetachedSignature> ("detached", sig), true);

    EXPECT_EQ(OpenPGP::Verify::detached_signature(pri, MESSAGE, sig), true);
}

TEST(gpg, verify_binary){

    OpenPGP::SecretKey pri;
    ASSERT_EQ(read_pgp <OpenPGP::SecretKey> ("Alicepri", pri), true);

    OpenPGP::Message sig;
    ASSERT_EQ(read_pgp <OpenPGP::Message> ("signature", sig), true);

    EXPECT_EQ(OpenPGP::Verify::binary(pri, sig), true);
}

TEST(gpg, verify_cleartext){

    OpenPGP::SecretKey pri;
    ASSERT_EQ(read_pgp <OpenPGP::SecretKey> ("Alicepri", pri), true);

    OpenPGP::CleartextSignature clearsig;
    ASSERT_EQ(read_pgp <OpenPGP::CleartextSignature> ("clearsign", clearsig), true);

    EXPECT_EQ(clearsig.get_message(), MESSAGE.substr(0, MESSAGE.size() - 1)); // final newline is removed

    const OpenPGP::DetachedSignature key = clearsig.get_sig();
    const OpenPGP::PGP::Packets packets = key.get_packets();

    EXPECT_EQ(packets.size(), (OpenPGP::PGP::Packets::size_type) 1);

    ASSERT_EQ(packets[0] -> get_tag(), OpenPGP::Packet::SIGNATURE);

    const OpenPGP::Packet::Tag2::Ptr tag2 = std::dynamic_pointer_cast <OpenPGP::Packet::Tag2> (packets[0]);

    EXPECT_EQ(tag2 -> get_version(), (uint8_t)    4);
    EXPECT_EQ(tag2 -> get_size(), (std::size_t) 284);

    EXPECT_EQ(tag2 -> get_pka(), OpenPGP::PKA::ID::RSA_ENCRYPT_OR_SIGN);
    EXPECT_EQ(tag2 -> get_hash(), OpenPGP::Hash::ID::SHA1);
    EXPECT_EQ(tag2 -> get_left16(), "\x77\x8e");

    const OpenPGP::PKA::Values mpi = tag2 -> get_mpi();
    ASSERT_EQ(mpi.size(), (OpenPGP::PKA::Values::size_type) 1);
    EXPECT_EQ(OpenPGP::bitsize(mpi[0]), (std::size_t) 2047);
    EXPECT_EQ(OpenPGP::mpitohex(mpi[0]), "4d1df9039259b42782d30c91e29ae9f7ac20e623e86c25e069ca441afc4a1cec30c9486c1a17799e8b1d39dcb8240b74269d083ad62f09232195fef84abca886c45f5263beaa02dde4b0a3ea4ff659d3bcaab5509a9d265e6326d560f8d0662ec07347fbf360e2421f851f12d923ceac84139245747ef3180b836eb4785428c9ea6fe5842e56d6ba7582b278b5ca68ad6bcb7a630568f800517264ddce690c96ab5925603be83b55207df45483c9cf57f88556e5a806910fb213e5cb3ee02bc45e4e4a894ebaec6967555cfae7615657a239a4523f56d0e399ccd35118d2b4daca2180b0fe24d8d258c59f8203dcb8579f8980802321ab274992bcf23d9d0095");

    // hashed
    {
        const OpenPGP::Packet::Tag2::Subpackets hashed = tag2 -> get_hashed_subpackets();
        ASSERT_EQ(hashed.size(), (std::size_t) 1);

        const OpenPGP::Subpacket::Tag2::Sub::Ptr s0 = hashed[0];
        ASSERT_EQ(s0 -> get_type(), OpenPGP::Subpacket::Tag2::SIGNATURE_CREATION_TIME);

        const OpenPGP::Subpacket::Tag2::Sub2::Ptr sub2 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub2> (s0);
        EXPECT_EQ(sub2 -> get_time(), get_utc(2014, 06, 22, 13, 05, 41));
    }
    // unhashed
    {
        const OpenPGP::Packet::Tag2::Subpackets unhashed = tag2 -> get_unhashed_subpackets();
        ASSERT_EQ(unhashed.size(), (OpenPGP::Packet::Tag2::Subpackets::size_type) 1);

        const OpenPGP::Subpacket::Tag2::Sub::Ptr s0 = unhashed[0];
        ASSERT_EQ(s0 -> get_type(), OpenPGP::Subpacket::Tag2::ISSUER);

        const OpenPGP::Subpacket::Tag2::Sub16::Ptr sub16 = std::dynamic_pointer_cast <OpenPGP::Subpacket::Tag2::Sub16> (s0);
        EXPECT_EQ(sub16 -> get_keyid(), "\xd5\xd7\xda\x71\xc3\x54\x96\x0e");
    }

    EXPECT_EQ(OpenPGP::Verify::cleartext_signature(pri, clearsig), true);
}

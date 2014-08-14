#include <gtest/gtest.h>

#include "PGP.h"
#include "PGPCleartextSignature.h"
#include "decrypt.h"

#include "testvectors/gpg/pgpencrypt.h"
#include "testvectors/gpg/pgpprikey.h"
#include "testvectors/gpg/pgppubkey.h"
#include "testvectors/gpg/pgprevoke.h"
#include "testvectors/gpg/pgpsign.h"

static const std::string PASSPHRASE = "test";

time_t get_utc(int year, int month, int day, int hour, int minute, int second) {
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
    utc = tmp->tm_hour;
    tmp = localtime(&result);
    local = tmp->tm_hour;
    if ( utc != local ) {
        int diff = local - utc;
        if ( diff < 0 && diff < -12 ) {
            diff += 24;
        } else if (diff > 0 && diff > 12) {
            diff -= 24;
        }
        result += diff*60*60;
    }
    return result;
}

TEST(PGPTest, test_gpg_public_key) {

    std::string in = GPG_PUBKEY_ALICE;
    PGPPublicKey pgp(in);

    auto packets = pgp.get_packets();
    ASSERT_EQ(packets.size(), 5);

    Packet::Ptr
            p0 = packets[0],
            p1 = packets[1],
            p2 = packets[2],
            p3 = packets[3],
            p4 = packets[4];

    ASSERT_EQ(p0->get_tag(), 6);
    ASSERT_EQ(p1->get_tag(), 13);
    ASSERT_EQ(p2->get_tag(), 2);
    ASSERT_EQ(p3->get_tag(), 14);
    ASSERT_EQ(p4->get_tag(), 2);
    Tag6::Ptr  pubkey = std::dynamic_pointer_cast<Tag6>(p0);
    Tag13::Ptr userid = std::dynamic_pointer_cast<Tag13>(p1);
    Tag14::Ptr subkey = std::dynamic_pointer_cast<Tag14>(p3);
    Tag2::Ptr  pubsig = std::dynamic_pointer_cast<Tag2>(p2),
               subsig = std::dynamic_pointer_cast<Tag2>(p4);

    EXPECT_EQ(pubkey->get_version(), 4);
    EXPECT_EQ(subkey->get_version(), 4);
    EXPECT_EQ(pubsig->get_version(), 4);
    EXPECT_EQ(subsig->get_version(), 4);
    EXPECT_EQ(userid->get_version(), 0);  // undefined

    EXPECT_EQ(pubkey->get_size(), 269);
    EXPECT_EQ(userid->get_size(), 36);
    EXPECT_EQ(pubsig->get_size(), 312);
    EXPECT_EQ(subkey->get_size(), 269);
    EXPECT_EQ(subsig->get_size(), 287);

    time_t gen_time = get_utc(2014, 6, 22, 12, 50, 48);

    // pubkey
    {
        EXPECT_EQ(pubkey->get_time(), gen_time); // 2014-06-22T12:50:48 UTC
        EXPECT_EQ(pubkey->get_pka(), 1);             // RSA
        auto mpi = pubkey->get_mpi();
        auto n = mpi[0], e = mpi[1];
        EXPECT_EQ(bitsize(n), 2048);  // 2048-bit
        EXPECT_EQ(mpitohex(n), "bc047e94d471f3ccbd525d6a6f8e17f7b1f00527c722c3913ce787fbd0090e3af8be7e59410f63b3983a9507b761045c11510e62f5a8cfbcdc180976a4c225737b8e06d8531f38c6eaa996954d5521a6763231f07c2b43605d052abdf39d6c668ac94bc89f543052d050530c70c48a49a970867c00178f9076dd0e151d254632767b2926e9baa22c6d0c213f1f45de74991396d7e8d10508cf679139410ab311b1279dd3c0d37facca54d523cd14a3df488eb8f592c5a19bcfede67c8170815c588adf39d188197da40492aac5b183c303f6ef23b0b5e48ff73b2d806afb0fb4f16ba32769249d3a7ca0ef0b9b3d57852dc9a979b6d56f3dc170e28dcb2e536d");
        EXPECT_EQ(bitsize(e), 17);    // 17-bit
        EXPECT_EQ(e, 0x10001);
    }

    // userid
    {
        EXPECT_EQ(userid->raw(), "alice (test key) <alice@example.com>");
    }

    // pubsig
    {
        EXPECT_EQ(pubsig->get_type(), 0x13); // Positive certification of a User ID and Public-Key packet
        EXPECT_EQ(pubsig->get_pka(), 1);     // RSA
        EXPECT_EQ(pubsig->get_hash(), 2);    // SHA1
        EXPECT_EQ(pubsig->get_left16(), "\x04\x5e");
        auto mpi = pubsig->get_mpi();
        ASSERT_EQ(mpi.size(), 1);
        EXPECT_EQ(bitsize(mpi[0]), 2047); // 2047-bit
        EXPECT_EQ(mpitohex(mpi[0]), "688a18a258f866cf50f1c938dc15b11298da0bfbd680241f52545af5023722858cdfb579da22e66dae36dff9a817f797192e95b7074bab49381acb837f1216d4e8e3c2de2fb5547a515b5236823bcb4b3bca1a68455fa984c4dc21b1a5af2308aea580c0ae2ca3f5db343beaa559524702d09e40d1923314ef0f15646acec91b9c6d9cba9d9b87fa78626a522ae1520f0aed361df00f8191a9ecb1fb12732e9f6e5e1c4bece397e4dcfbacd41918882c2dfa75b98b54587f0cd61195bdce41b690329a746c6e37b7e2ef9b06206bf280ff93ec0b891929790492a9971acaa9e7e141585ca41800dd462b6f8235c0f1e0b691a5054da8f90295f5949e22fb5e5c");
        // pubsig/hashed
        auto pubsub = pubsig->get_hashed_subpackets();
        ASSERT_EQ(pubsub.size(), 7);
        Subpacket::Ptr
                ps0 = pubsub[0],
                ps1 = pubsub[1],
                ps2 = pubsub[2],
                ps3 = pubsub[3],
                ps4 = pubsub[4],
                ps5 = pubsub[5],
                ps6 = pubsub[6];

        ASSERT_EQ(ps0->get_type(), 2);
        ASSERT_EQ(ps1->get_type(), 27);
        ASSERT_EQ(ps2->get_type(), 11);
        ASSERT_EQ(ps3->get_type(), 21);
        ASSERT_EQ(ps4->get_type(), 22);
        ASSERT_EQ(ps5->get_type(), 30);
        ASSERT_EQ(ps6->get_type(), 23);
        Tag2Sub2::Ptr  pubsub2  = std::dynamic_pointer_cast<Tag2Sub2>(ps0);
        Tag2Sub27::Ptr pubsub27 = std::dynamic_pointer_cast<Tag2Sub27>(ps1);
        Tag2Sub11::Ptr pubsub11 = std::dynamic_pointer_cast<Tag2Sub11>(ps2);
        Tag2Sub21::Ptr pubsub21 = std::dynamic_pointer_cast<Tag2Sub21>(ps3);
        Tag2Sub22::Ptr pubsub22 = std::dynamic_pointer_cast<Tag2Sub22>(ps4);
        Tag2Sub30::Ptr pubsub30 = std::dynamic_pointer_cast<Tag2Sub30>(ps5);
        Tag2Sub23::Ptr pubsub23 = std::dynamic_pointer_cast<Tag2Sub23>(ps6);

        // pubsig/sub2
        {
            EXPECT_EQ(pubsub2->get_time(), gen_time); // 2014-06-22T12:50:48 UTC
        }
        // pubsig/sub27
        {
            EXPECT_EQ(pubsub27->get_flags(), (1 | 2));
        }
        // pubsig/sub11
        {
            std::string psa = pubsub11->get_psa();
            EXPECT_EQ(psa.size(), 5);
            EXPECT_NE(psa.find(9), std::string::npos); // AES 256-bit
            EXPECT_NE(psa.find(8), std::string::npos); // AES 192-bit
            EXPECT_NE(psa.find(7), std::string::npos); // AES 128-bit
            EXPECT_NE(psa.find(3), std::string::npos); // CAST5
            EXPECT_NE(psa.find(2), std::string::npos); // TDES
        }
        // pubsig/sub21
        {
            std::string pha = pubsub21->get_pha();
            EXPECT_EQ(pha.size(), 5);
            EXPECT_NE(pha.find(8), std::string::npos);  // SHA256
            EXPECT_NE(pha.find(2), std::string::npos);  // SHA1
            EXPECT_NE(pha.find(9), std::string::npos);  // SHA384
            EXPECT_NE(pha.find(10), std::string::npos); // SHA512
            EXPECT_NE(pha.find(11), std::string::npos); // SHA224
        }
        // pubsig/sub22
        {
            std::string pca = pubsub22->get_pca();
            EXPECT_EQ(pca.size(), 3);
            EXPECT_NE(pca.find(2), std::string::npos); // ZLIB
            EXPECT_NE(pca.find(3), std::string::npos); // BZip2
            EXPECT_NE(pca.find(1), std::string::npos); // ZIP
        }
        // pubsig/sub30
        {
            EXPECT_EQ(pubsub30->get_flags(), 1); // Modification Detection
        }
        // pubsig/sub23
        {
            EXPECT_EQ(pubsub23->get_flags(), static_cast<char>(0x80)); // No-modify
        }

        // pubsig/unhashed
        auto uh_pubsub = pubsig->get_unhashed_subpackets();
        ASSERT_EQ(uh_pubsub.size(), 1);
        Subpacket::Ptr uhps0 = uh_pubsub[0];
        ASSERT_EQ(uhps0->get_type(), 16);
        Tag2Sub16::Ptr pubsub16 = std::dynamic_pointer_cast<Tag2Sub16>(uhps0);
        // pubsig/sub16
        {
            EXPECT_EQ(pubsub16->get_keyid(), "\xd5\xd7\xda\x71\xc3\x54\x96\x0e");
        }
    }

    // subkey
    {
        EXPECT_EQ(subkey->get_time(), gen_time); // 2014-06-22T12:50:48 UTC
        EXPECT_EQ(subkey->get_pka(), 1);             // RSA
        auto mpi = subkey->get_mpi();
        auto n = mpi[0], e = mpi[1];
        EXPECT_EQ(bitsize(n), 2048);  // 2048-bit
        EXPECT_EQ(mpitohex(n), "d98aac4e3f499e2264aebd71ea0e7d8a8d4690ff73d09125cd197892f1bb59492b8523dc5e4a0b9e0702babf65a71113d96a7ba2ee37cdc2ae8b0b03c67b16c12bd67e6835e4de01cd84baba53fb3d22294252dbb2ba854d1fe25f473b6ac8141392697bc6049d3865d9a00f909971e3b1903758e11b13a4661cf79080beac6d9ddb9113dfa788d2fc38a073b8d2717d0e28721f37dc0f7b6eb9a389f8050fac387ba3dedaf32210995534df5188982d431d0f6d93daa48b10ae7a337571f8bbcea59c9677789eedc2fcf2572f3d2ace9ae12b4817aa08d9541a423d0e60fd657f332c3fe47eef242e56715d25422971b6381a1e6a52bbae574da0077f83a535");
        EXPECT_EQ(bitsize(e), 17);    // 17-bit
        EXPECT_EQ(e, 0x10001);
    }

    // subsig
    {
        EXPECT_EQ(subsig->get_type(), 0x18); // Subkey Binding Signature
        EXPECT_EQ(subsig->get_pka(), 1);     // RSA
        EXPECT_EQ(subsig->get_hash(), 2);    // SHA1
        EXPECT_EQ(subsig->get_left16(), "\x9a\xeb");
        EXPECT_EQ(bitsize(subsig->get_mpi()[0]), 2047); // 2047-bit

        // subsig/hashed
        auto subsub = subsig->get_hashed_subpackets();
        ASSERT_EQ(subsub.size(), 2);
        Subpacket::Ptr
                ss0 = subsub[0],
                ss1 = subsub[1];

        ASSERT_EQ(ss0->get_type(), 2);
        ASSERT_EQ(ss1->get_type(), 27);

        Tag2Sub2::Ptr  subsub2  = std::dynamic_pointer_cast<Tag2Sub2>(ss0);
        Tag2Sub27::Ptr subsub27 = std::dynamic_pointer_cast<Tag2Sub27>(ss1);
        // subsig/sub2
        {
            EXPECT_EQ(subsub2->get_time(), gen_time); // 2014-06-22T12:50:48 UTC
        }
        // subsig/sub27
        {
            EXPECT_EQ(subsub27->get_flags(), (4 | 8));
        }

        // subsig/unhashed
        auto uh_subsub = subsig->get_unhashed_subpackets();
        ASSERT_EQ(uh_subsub.size(), 1);
        Subpacket::Ptr uhss0 = uh_subsub[0];
        ASSERT_EQ(uhss0->get_type(), 16);
        Tag2Sub16::Ptr subsub16 = std::dynamic_pointer_cast<Tag2Sub16>(uhss0);
        // subsig/sub16
        {
            EXPECT_EQ(subsub16->get_keyid(), "\xd5\xd7\xda\x71\xc3\x54\x96\x0e");
        }
    }

}

TEST(PGPTest, test_gpg_private_key) {

    std::string in = GPG_PRIKEY_ALICE;
    PGPSecretKey pgp(in);

    auto packets = pgp.get_packets();
    ASSERT_EQ(packets.size(), 5);

    Packet::Ptr
            p0 = packets[0],
            p1 = packets[1],
            p2 = packets[2],
            p3 = packets[3],
            p4 = packets[4];

    ASSERT_EQ(p0->get_tag(), 5);
    ASSERT_EQ(p1->get_tag(), 13);
    ASSERT_EQ(p2->get_tag(), 2);
    ASSERT_EQ(p3->get_tag(), 7);
    ASSERT_EQ(p4->get_tag(), 2);
    Tag5::Ptr  seckey = std::dynamic_pointer_cast<Tag5>(p0);
    Tag13::Ptr userid = std::dynamic_pointer_cast<Tag13>(p1);
    Tag7::Ptr  subkey = std::dynamic_pointer_cast<Tag7>(p3);
    Tag2::Ptr  pubsig = std::dynamic_pointer_cast<Tag2>(p2),
               subsig = std::dynamic_pointer_cast<Tag2>(p4);

    EXPECT_EQ(seckey->get_version(), 4);
    EXPECT_EQ(subkey->get_version(), 4);
    EXPECT_EQ(pubsig->get_version(), 4);
    EXPECT_EQ(subsig->get_version(), 4);
    EXPECT_EQ(userid->get_version(), 0);  // undefined

    EXPECT_EQ(seckey->get_size(), 958);
    EXPECT_EQ(userid->get_size(), 36);
    EXPECT_EQ(pubsig->get_size(), 312);
    EXPECT_EQ(subkey->get_size(), 958);
    EXPECT_EQ(subsig->get_size(), 287);

    time_t gen_time = get_utc(2014, 6, 22, 12, 50, 48);

    // seckey
    {
        EXPECT_EQ(seckey->get_time(), gen_time); // 2014-06-22T12:50:48 UTC
        EXPECT_EQ(seckey->get_pka(), 1); // RSA
        auto mpi = seckey->get_mpi();
        auto n = mpi[0], e = mpi[1];
        EXPECT_EQ(bitsize(n), 2048);  // 2048-bit
        EXPECT_EQ(mpitohex(n), "bc047e94d471f3ccbd525d6a6f8e17f7b1f00527c722c3913ce787fbd0090e3af8be7e59410f63b3983a9507b761045c11510e62f5a8cfbcdc180976a4c225737b8e06d8531f38c6eaa996954d5521a6763231f07c2b43605d052abdf39d6c668ac94bc89f543052d050530c70c48a49a970867c00178f9076dd0e151d254632767b2926e9baa22c6d0c213f1f45de74991396d7e8d10508cf679139410ab311b1279dd3c0d37facca54d523cd14a3df488eb8f592c5a19bcfede67c8170815c588adf39d188197da40492aac5b183c303f6ef23b0b5e48ff73b2d806afb0fb4f16ba32769249d3a7ca0ef0b9b3d57852dc9a979b6d56f3dc170e28dcb2e536d");
        EXPECT_EQ(bitsize(e), 17);    // 17-bit
        EXPECT_EQ(e, 0x10001);
        EXPECT_EQ(seckey->get_sym(), 3); // CAST5
        EXPECT_EQ(seckey->get_IV(), "\x47\xdb\x0a\x37\x11\x76\xb3\x5d");
        auto secs2k = seckey->get_s2k();
        EXPECT_EQ(secs2k->get_type(), 3);  // Salted-S2K
        EXPECT_EQ(secs2k->get_hash(), 2);  // SHA1
        S2K3::Ptr secs2k3 = std::dynamic_pointer_cast<S2K3>(secs2k);
        EXPECT_EQ(secs2k3->get_count(), 96);
        auto secmpi = decrypt_secret_key(seckey, PASSPHRASE);
        EXPECT_EQ(secmpi.size(), 4);
        EXPECT_EQ(mpitohex(secmpi[0]), "03949bbb19be693235e62b7ef33fcd6f5813afb7d8db542c99a3921eed10a3153050c993e30dbe6c454939836d27bb5f2c137323899bccd48fd909efe5b93b60a645daaf6aa3d1b8ee08fed72d56158bd13cb62c73e34ba0ed82f6ba76390eff43ea71f110ae7e814ad3fa5e8007dd5750acc92873aaff320ea56cf0ade4dc7994ac78d9dfc567ead2589f514ac4a95d2a28685d1f593129f7f82fdaca2e4e87b4b223ca3d6c742370bfba2a4954b1c7bcf4290addad26c2a52ea4a5d664a8c32cf729bb1c783fa817ef50c5432a3c1c73ef9d1e08ecf9780d5f3c8667ade01f397270b2919d632cba1ccd4c0861cb8420f4eabe8606115342657a281f1051d1");
        EXPECT_EQ(mpitohex(secmpi[1]), "d03b3727809678a98fb4f94f9fde836efeaacafefd721ebb83c90dfebcc169a88944859afb2c4154c20d45a155d85bf692be56c1778b0bd94b77fd878d81bbe5584fbb28e716785821b1f4e0a3bffb7bc812c51394dc803d53afa261745092ed3169fcc7e2d125f2595a1555efc5f350be6654b050057839be3fc3ac1719453d");
        EXPECT_EQ(mpitohex(secmpi[2]), "e7262ff9b96de7b93a9977edebd1b424217c8e1edce2e1ac9e38493ef5e727b4fbbc64312e0a48823fa5e71292d939e724f2c5d32eed544be5e7bc3421b4b6031cd65b1d8531d24e1d44bd282edddb20f58abdd78722a18e4f62fde869381f5e6040e1163e399f7b7b614f17bb51038c23c57b1d87241d97dbc7e4b85e1909f1");
        EXPECT_EQ(mpitohex(secmpi[3]), "a5b011afc09d933d7f75b58e750bee1f05bf95d7bc354d3989eaa58cbdf85c367536b11dd29e016fe90f419288765e50af6e00a96660169716313f8d4080ce407cbad43a912e23170552d97a0465ab90a0a6b879a85bef0c2bbae100cbfc2927a01a0842fe8c2c6234149b35c05075438f7f4e2a3d5f19f427f423b868c0dad1");
    }

    // userid
    {
        EXPECT_EQ(userid->raw(), "alice (test key) <alice@example.com>");
    }

    // pubsig (same as test_gpg_public_key)
    {
        EXPECT_EQ(pubsig->get_type(), 0x13); // Positive certification of a User ID and Public-Key packet
        EXPECT_EQ(pubsig->get_pka(), 1);     // RSA
        EXPECT_EQ(pubsig->get_hash(), 2);    // SHA1
        EXPECT_EQ(pubsig->get_left16(), "\x04\x5e");
        auto mpi = pubsig->get_mpi();
        ASSERT_EQ(mpi.size(), 1);
        EXPECT_EQ(bitsize(mpi[0]), 2047); // 2047-bit
        EXPECT_EQ(mpitohex(mpi[0]), "688a18a258f866cf50f1c938dc15b11298da0bfbd680241f52545af5023722858cdfb579da22e66dae36dff9a817f797192e95b7074bab49381acb837f1216d4e8e3c2de2fb5547a515b5236823bcb4b3bca1a68455fa984c4dc21b1a5af2308aea580c0ae2ca3f5db343beaa559524702d09e40d1923314ef0f15646acec91b9c6d9cba9d9b87fa78626a522ae1520f0aed361df00f8191a9ecb1fb12732e9f6e5e1c4bece397e4dcfbacd41918882c2dfa75b98b54587f0cd61195bdce41b690329a746c6e37b7e2ef9b06206bf280ff93ec0b891929790492a9971acaa9e7e141585ca41800dd462b6f8235c0f1e0b691a5054da8f90295f5949e22fb5e5c");
        // pubsig/hashed
        auto pubsub = pubsig->get_hashed_subpackets();
        ASSERT_EQ(pubsub.size(), 7);
        Subpacket::Ptr
                ps0 = pubsub[0],
                ps1 = pubsub[1],
                ps2 = pubsub[2],
                ps3 = pubsub[3],
                ps4 = pubsub[4],
                ps5 = pubsub[5],
                ps6 = pubsub[6];

        ASSERT_EQ(ps0->get_type(), 2);
        ASSERT_EQ(ps1->get_type(), 27);
        ASSERT_EQ(ps2->get_type(), 11);
        ASSERT_EQ(ps3->get_type(), 21);
        ASSERT_EQ(ps4->get_type(), 22);
        ASSERT_EQ(ps5->get_type(), 30);
        ASSERT_EQ(ps6->get_type(), 23);
        Tag2Sub2::Ptr  pubsub2  = std::dynamic_pointer_cast<Tag2Sub2>(ps0);
        Tag2Sub27::Ptr pubsub27 = std::dynamic_pointer_cast<Tag2Sub27>(ps1);
        Tag2Sub11::Ptr pubsub11 = std::dynamic_pointer_cast<Tag2Sub11>(ps2);
        Tag2Sub21::Ptr pubsub21 = std::dynamic_pointer_cast<Tag2Sub21>(ps3);
        Tag2Sub22::Ptr pubsub22 = std::dynamic_pointer_cast<Tag2Sub22>(ps4);
        Tag2Sub30::Ptr pubsub30 = std::dynamic_pointer_cast<Tag2Sub30>(ps5);
        Tag2Sub23::Ptr pubsub23 = std::dynamic_pointer_cast<Tag2Sub23>(ps6);

        // pubsig/sub2
        {
            EXPECT_EQ(pubsub2->get_time(), gen_time); // 2014-06-22T12:50:48 UTC
        }
        // pubsig/sub27
        {
            EXPECT_EQ(pubsub27->get_flags(), (1 | 2));
        }
        // pubsig/sub11
        {
            std::string psa = pubsub11->get_psa();
            EXPECT_EQ(psa.size(), 5);
            EXPECT_NE(psa.find(9), std::string::npos); // AES 256-bit
            EXPECT_NE(psa.find(8), std::string::npos); // AES 192-bit
            EXPECT_NE(psa.find(7), std::string::npos); // AES 128-bit
            EXPECT_NE(psa.find(3), std::string::npos); // CAST5
            EXPECT_NE(psa.find(2), std::string::npos); // TDES
        }
        // pubsig/sub21
        {
            std::string pha = pubsub21->get_pha();
            EXPECT_EQ(pha.size(), 5);
            EXPECT_NE(pha.find(8), std::string::npos);  // SHA256
            EXPECT_NE(pha.find(2), std::string::npos);  // SHA1
            EXPECT_NE(pha.find(9), std::string::npos);  // SHA384
            EXPECT_NE(pha.find(10), std::string::npos); // SHA512
            EXPECT_NE(pha.find(11), std::string::npos); // SHA224
        }
        // pubsig/sub22
        {
            std::string pca = pubsub22->get_pca();
            EXPECT_EQ(pca.size(), 3);
            EXPECT_NE(pca.find(2), std::string::npos); // ZLIB
            EXPECT_NE(pca.find(3), std::string::npos); // BZip2
            EXPECT_NE(pca.find(1), std::string::npos); // ZIP
        }
        // pubsig/sub30
        {
            EXPECT_EQ(pubsub30->get_flags(), 1); // Modification Detection
        }
        // pubsig/sub23
        {
            EXPECT_EQ(pubsub23->get_flags(), static_cast<char>(0x80)); // No-modify
        }

        // pubsig/unhashed
        auto uh_pubsub = pubsig->get_unhashed_subpackets();
        ASSERT_EQ(uh_pubsub.size(), 1);
        Subpacket::Ptr uhps0 = uh_pubsub[0];
        ASSERT_EQ(uhps0->get_type(), 16);
        Tag2Sub16::Ptr pubsub16 = std::dynamic_pointer_cast<Tag2Sub16>(uhps0);
        // pubsig/sub16
        {
            EXPECT_EQ(pubsub16->get_keyid(), "\xd5\xd7\xda\x71\xc3\x54\x96\x0e");
        }
    }

    // subkey
    {
        EXPECT_EQ(subkey->get_time(), gen_time); // 2014-06-22T12:50:48 UTC
        EXPECT_EQ(subkey->get_pka(), 1); // RSA
        auto mpi = subkey->get_mpi();
        auto n = mpi[0], e = mpi[1];
        EXPECT_EQ(bitsize(n), 2048);  // 2048-bit
        EXPECT_EQ(mpitohex(n), "d98aac4e3f499e2264aebd71ea0e7d8a8d4690ff73d09125cd197892f1bb59492b8523dc5e4a0b9e0702babf65a71113d96a7ba2ee37cdc2ae8b0b03c67b16c12bd67e6835e4de01cd84baba53fb3d22294252dbb2ba854d1fe25f473b6ac8141392697bc6049d3865d9a00f909971e3b1903758e11b13a4661cf79080beac6d9ddb9113dfa788d2fc38a073b8d2717d0e28721f37dc0f7b6eb9a389f8050fac387ba3dedaf32210995534df5188982d431d0f6d93daa48b10ae7a337571f8bbcea59c9677789eedc2fcf2572f3d2ace9ae12b4817aa08d9541a423d0e60fd657f332c3fe47eef242e56715d25422971b6381a1e6a52bbae574da0077f83a535");
        EXPECT_EQ(bitsize(e), 17);    // 17-bit
        EXPECT_EQ(e, 0x10001);
        EXPECT_EQ(subkey->get_sym(), 3); // CAST5
        EXPECT_EQ(subkey->get_IV(), "\x22\x01\xe4\x2a\xc6\x81\x4d\x35");
        auto subs2k = subkey->get_s2k();
        EXPECT_EQ(subs2k->get_type(), 3);  // Salted-S2K
        EXPECT_EQ(subs2k->get_hash(), 2);  // SHA1
        S2K3::Ptr subs2k3 = std::dynamic_pointer_cast<S2K3>(subs2k);
        EXPECT_EQ(subs2k3->get_count(), 96);
        auto secmpi = decrypt_secret_key(subkey, PASSPHRASE);
        EXPECT_EQ(secmpi.size(), 4);
        EXPECT_EQ(mpitohex(secmpi[0]), "6275226e19b3ba880b7490d6855e0090dc47136a22a343864dd118e2bcd893dd0b7eeb4f9a373e11cc4f7e7110d36fe5c171b1ba78c1b5f5466534db851201a6f52dd3b15baf1591d05021e92208644f594824d33d8db0b64ad77c52f37fed4534e47fac5edf88bed54e0d64ee079ce5b66034c49bc152ff059e57a7c5b546b9526a98fa7d2371d8843887c7708a5a5db82f3520cb7d784602b145e4c3de287fc2dd50a9b9c99d34176852e1024cf1eac2d9039b5a690991ee2f1b178c308587f62801955d3254530203b039823aec6d50bd40d791711fff815c76cd99164725cd43f4c2134c1053f63281d4a6d210809f6b686a3db45d66ebd85ac16883e413");
        EXPECT_EQ(mpitohex(secmpi[1]), "ebc63b9c2c5002d77f3f3261ce3ebdd4710827b180f0a2b5b847c2e5e6365903fc8ae73078666737850c0575d1ef558b0d77e3039f1e4cef6a97e90ccc70bec4459f4140725d98f2d275f81da1326b34cf1e0b0b69466e878e2c98823732ea5baa0cff7d687bf44590a0bab69f6d7182dcfb8ec20197fe9533730ce0549f991b");
        EXPECT_EQ(mpitohex(secmpi[2]), "ec3409ddb6f104384a7f4788ba73164d8420bdbc240d815c6e615603955ca128a388c21c0c19fe42be806922c2708d37efefd57a52f1fb777cfad002f2ba4f6c4c7119734340f13639b02a5c66d9b98048388ab3e97fca8f47fb07d360ed629762c045929f4f60c37c34a52ae75a12be68cb9644d7867de03029c3dccc736fef");
        EXPECT_EQ(mpitohex(secmpi[3]), "0547d7351f3047b5d4728cfed246eef218e4d0840d5f5edb9faf723da93bbb914e806a8ea569889eada1a37a6dd69da1c7f6f2e21d8fc6622dc759adb97a3e4003fcd7a499bcecebf9b7f4be958c3486501810ce321b2c343d1d19aae7f6b6454b5a7a5c551986f49e904b63a6f7cc32ccafa78bb7a7696d627ba67489cdcc89");
    }

    // subsig (same as test_gpg_public_key)
    {
        EXPECT_EQ(subsig->get_type(), 0x18); // Subkey Binding Signature
        EXPECT_EQ(subsig->get_pka(), 1);     // RSA
        EXPECT_EQ(subsig->get_hash(), 2);    // SHA1
        EXPECT_EQ(subsig->get_left16(), "\x9a\xeb");
        EXPECT_EQ(bitsize(subsig->get_mpi()[0]), 2047); // 2047-bit

        // subsig/hashed
        auto subsub = subsig->get_hashed_subpackets();
        ASSERT_EQ(subsub.size(), 2);
        Subpacket::Ptr
                ss0 = subsub[0],
                ss1 = subsub[1];

        ASSERT_EQ(ss0->get_type(), 2);
        ASSERT_EQ(ss1->get_type(), 27);

        Tag2Sub2::Ptr  subsub2  = std::dynamic_pointer_cast<Tag2Sub2>(ss0);
        Tag2Sub27::Ptr subsub27 = std::dynamic_pointer_cast<Tag2Sub27>(ss1);
        // subsig/sub2
        {
            EXPECT_EQ(subsub2->get_time(), gen_time); // 2014-06-22T12:50:48 UTC
        }
        // subsig/sub27
        {
            EXPECT_EQ(subsub27->get_flags(), (4 | 8));
        }

        // subsig/unhashed
        auto uh_subsub = subsig->get_unhashed_subpackets();
        ASSERT_EQ(uh_subsub.size(), 1);
        Subpacket::Ptr uhss0 = uh_subsub[0];
        ASSERT_EQ(uhss0->get_type(), 16);
        Tag2Sub16::Ptr subsub16 = std::dynamic_pointer_cast<Tag2Sub16>(uhss0);
        // subsig/sub16
        {
            EXPECT_EQ(subsub16->get_keyid(), "\xd5\xd7\xda\x71\xc3\x54\x96\x0e");
        }
    }

}

TEST(PGPTest, test_gpg_revoke) {

    std::string in = GPG_REVOKE3_ALICE;
    PGPPublicKey pgp(in);

    auto packets = pgp.get_packets();
    ASSERT_EQ(packets.size(), 1);

    Packet::Ptr p0 = packets[0];

    ASSERT_EQ(p0->get_tag(), 2);
    Tag2::Ptr revsig = std::dynamic_pointer_cast<Tag2>(p0);

    EXPECT_EQ(revsig->get_version(), 4);
    EXPECT_EQ(revsig->get_size(), 287);

    EXPECT_EQ(revsig->get_type(), 0x20);  // Key revocation signature
    EXPECT_EQ(revsig->get_pka(), 1);      // RSA
    EXPECT_EQ(revsig->get_hash(), 2);     // SHA1
    EXPECT_EQ(revsig->get_left16(), "\xcf\xb9");

    auto mpi = revsig->get_mpi();
    ASSERT_EQ(mpi.size(), 1);

    auto sign = mpi[0];
    EXPECT_EQ(bitsize(sign), 2045);
    EXPECT_EQ(mpitohex(sign), "133edac0fa9b187e05f8ce8dade82f31d3a266190f911b79aed0974952601b3effeed8a1a1dca9f742292a308be8cac43ff2c801ef901c06c6c6a520736dfc4b02c8f92af7a99a03f89d3d62df9844cb6271e409200a7fb6d2e29fe3e72be5305004a39765bf7f02be6dcde47e44131e5529d397592432a74decc6db6cd627848f1535a6166103e6a17f99256fead668fdeb37a72c3f0bc0c4795db324da138d38c37011d5b071ecce77fb84da464eaa6a75b2e1ab6ffa6653b0539149e5f92cfb0389d843f26cabcc41f0d623966734b2a7fa110430b29f1a7854ae5affbf9e228bbb440152242542585c7a38b95a541a8d9afccffd6c227b0a11bcd60b2bc7");

    // hashed
    {
        auto hashed = revsig->get_hashed_subpackets();
        ASSERT_EQ(hashed.size(), 2);

        Subpacket::Ptr
                s0 = hashed[0],
                s1 = hashed[1];

        ASSERT_EQ(s0->get_type(), 2);
        ASSERT_EQ(s1->get_type(), 29);

        Tag2Sub2::Ptr sub2   = std::dynamic_pointer_cast<Tag2Sub2>(s0);
        Tag2Sub29::Ptr sub29 = std::dynamic_pointer_cast<Tag2Sub29>(s1);

        // sub2
        {
            EXPECT_EQ(sub2->get_time(), get_utc(2014, 6, 22, 13, 03, 49));
        }
        // sub29
        {
            EXPECT_EQ(sub29->get_code(), 03);  // Key is no longer used
            EXPECT_EQ(sub29->get_reason(), ""); // (empty string)
        }
    }
    // unhashed
    {
        auto unhashed = revsig->get_unhashed_subpackets();
        ASSERT_EQ(unhashed.size(), 1);

        Subpacket::Ptr s0 = unhashed[0];
        ASSERT_EQ(s0->get_type(), 16);

        Tag2Sub16::Ptr sub16 = std::dynamic_pointer_cast<Tag2Sub16>(s0);
        EXPECT_EQ(sub16->get_keyid(), "\xd5\xd7\xda\x71\xc3\x54\x96\x0e");
    }


}

TEST(PGPTest, test_gpg_pka_encrypt_anonymous) {

    std::string in = GPG_PKA_ENCRYPT_TO_ALICE;
    PGPMessage pgp(in);

    auto packets = pgp.get_packets();
    ASSERT_EQ(packets.size(), 2);

    Packet::Ptr
            p0 = packets[0],
            p1 = packets[1];
    ASSERT_EQ(p0->get_tag(), 1);
    ASSERT_EQ(p1->get_tag(), 18);

    Tag1::Ptr  tag1  = std::dynamic_pointer_cast<Tag1>(p0);
    Tag18::Ptr tag18 = std::dynamic_pointer_cast<Tag18>(p1);

    EXPECT_EQ(tag1->get_version(), 3);
    EXPECT_EQ(tag18->get_version(), 1);

    EXPECT_EQ(tag1->get_size(), 268);
    EXPECT_EQ(tag18->get_size(), 109);

    // tag1
    {
        EXPECT_EQ(tag1->get_keyid(), "\x9f\x0f\xf4\x0f\xd2\x70\x61\xe1");
        EXPECT_EQ(tag1->get_pka(), 1); // RSA
        auto mpi = tag1->get_mpi();
        EXPECT_EQ(mpi.size(), 1);

        auto key = mpi[0];
        EXPECT_EQ(bitsize(key), 2047);
        EXPECT_EQ(mpitohex(key), "53031ee2f4be3ea2808d4fc7258f75a652af233ad5be0cd910e615ed266691e8ac584b3960b09c6c5d65c8c68d4caa46c5fe172cba7042aaf23da1a7f7ca61aad28015f88935ecd91f8501f3f9f85302a507c862aad2d9b7ed975bd5704aaeb57a0eebc2c393315dbe6e27b0e3f3347ccc677f1952dfa9ad2bbc6980386b9086729687113cac9842f6bf802aeb376932770844f8e96bea683be14557f57ba6b735f1f9c5f2e5a56acbf810f7aacc9d9657be659f707aec6a9a6aa3616a6b2e10a8dc94cccbca39cf80e1dc3205803a0ebe6614871be4a52117b0a39b0bc67919c3a2dbcfbb6ca0b21f39cd8f5374f3adf2adc97f7697f663ffa985c47e7de16f");
    }
    // tag18
    {
        std::string in_pri = GPG_PRIKEY_ALICE;
        PGPSecretKey pgp_pri(in_pri);
        std::string message = decrypt_pka(pgp_pri, pgp, PASSPHRASE, false);
        EXPECT_EQ(message, "The magic words are squeamish ossifrage\n");
    }
}

TEST(PGPTest, test_gpg_pka_encrypt) {

    std::string in = GPG_PKA_ENCRYPT_ALICE_TO_BOB;
    PGPMessage pgp(in);

    auto packets = pgp.get_packets();
    ASSERT_EQ(packets.size(), 2);

    Packet::Ptr
            p0 = packets[0],
            p1 = packets[1];
    ASSERT_EQ(p0->get_tag(), 1);
    ASSERT_EQ(p1->get_tag(), 18);

    Tag1::Ptr  tag1  = std::dynamic_pointer_cast<Tag1>(p0);
    Tag18::Ptr tag18 = std::dynamic_pointer_cast<Tag18>(p1);

    EXPECT_EQ(tag1->get_version(), 3);
    EXPECT_EQ(tag18->get_version(), 1);

    EXPECT_EQ(tag1->get_size(), 268);
    EXPECT_EQ(tag18->get_size(), 415);

    // tag1
    {
        EXPECT_EQ(tag1->get_keyid(), "\xd4\x23\x0a\xa3\x68\x61\xc3\x5d");
        EXPECT_EQ(tag1->get_pka(), 1); // RSA
        auto mpi = tag1->get_mpi();
        EXPECT_EQ(mpi.size(), 1);

        auto key = mpi[0];
        EXPECT_EQ(bitsize(key), 2048);
        EXPECT_EQ(mpitohex(key), "a60b39b03f08f2b083c9ffe6d77e4ca8d4edc9b6ff754f7e3e368c7bc06742763c5305e3fc279d7d667e1ae9067130e61e240b6be6e474fe80e625d86d536841f6d1161a1947a56f46d1d622f9f147f57a511e6216998be9a4966b92e0f751f69138f1b4c293608ad67b4b6d16e5ceed79cbdc09622e2bfd2a8de19d47a8946437c97ca5b95f6dc1a6a5ce86e041d6785962d64d8d96f830950bf112509a146dbd9322f54343a2ffba543859d81948890be209e6e1240cbe02b9e59d306e1697a32842f9e360596e3d866f6219b0131aa47577cf622778e6ae4de7a0db7af511e220f63f7ac0f8030e5e43583c362ebba9646d505a31d02018640b45e75c8fd7");
    }
    // tag18
    {
        std::string in_pri = GPG_PRIKEY_BOB;
        PGPSecretKey pgp_pri(in_pri);
        std::string message = decrypt_pka(pgp_pri, pgp, PASSPHRASE, false);
        EXPECT_EQ(message, "The magic words are squeamish ossifrage\n");
    }
}

TEST(PGPTest, test_gpg_symmetric_encrypt) {

    std::string in = GPG_SYMMETRIC_ENCRYPT_TO_ALICE;
    PGPMessage pgp(in);

    auto packets = pgp.get_packets();
    ASSERT_EQ(packets.size(), 3);

    Packet::Ptr
            p0 = packets[0],
            p1 = packets[1],
            p2 = packets[2];
    ASSERT_EQ(p0->get_tag(), 1);
    ASSERT_EQ(p1->get_tag(), 3);
    ASSERT_EQ(p2->get_tag(), 18);

    Tag1::Ptr tag1 = std::dynamic_pointer_cast<Tag1>(p0);
    Tag3::Ptr tag3 = std::dynamic_pointer_cast<Tag3>(p1);
    Tag18::Ptr tag18 = std::dynamic_pointer_cast<Tag18>(p2);

    EXPECT_EQ(tag1->get_version(), 3);
    EXPECT_EQ(tag3->get_version(), 4);
    EXPECT_EQ(tag18->get_version(), 1);

    EXPECT_EQ(tag1->get_size(), 268);
    EXPECT_EQ(tag3->get_size(), 46);
    EXPECT_EQ(tag18->get_size(), 109);

    // tag1
    {
        EXPECT_EQ(tag1->get_keyid(), "\x9f\x0f\xf4\x0f\xd2\x70\x61\xe1");
        EXPECT_EQ(tag1->get_pka(), 1); // RSA
        auto mpi = tag1->get_mpi();
        EXPECT_EQ(mpi.size(), 1);

        auto key = mpi[0];
        EXPECT_EQ(bitsize(key), 2046);
        EXPECT_EQ(mpitohex(key), "28982f6746b8acb2885b4eb7c07a5c2dfeae90e9c476550d90107719915340f906ca3016fbcd6e0854648e612e5a04c80d52e8184f6f890920769b074205c5b3a8286898a639f74a724e4e529709812feb25c77d9f344953a42760cdbf48adcbb81c9d829eb1010a2c8f6bc2334a12d3703db9a2ae8bbd2b3b2eeda805883c1111489d23abc2c7ac59d5535c633a115eaaafc3433cae7a36167b4e247f072fc9685554624a3840f52a8118f3c0d8b341063aa8be4ef17f8b5091e6034486b4fcbb34f2a865884600b7861468e8f999240c88818c46a83a3f753dce5930a2072e31019a4f11931494e9f6bedacbbd65d436acf314f36a3092cae5b67b33e36a37");
    }
    // tag3
    {
        EXPECT_EQ(tag3->get_sym(), 3);  // CAST5
        auto s2k = tag3->get_s2k();
        ASSERT_EQ(s2k->get_type(), 3);
        auto s2k3 = std::dynamic_pointer_cast<S2K3>(s2k);
        EXPECT_EQ(s2k3->get_hash(), 2);  // SHA1
        EXPECT_EQ(s2k3->get_salt(), "\x5f\x04\x1c\x5d\x66\x36\xc8\x95");
        EXPECT_EQ(s2k3->get_count(), 96);
        // TODO
        auto esk = tag3->get_esk();
    }
    // tag18
    {
        std::string in_pri = GPG_PRIKEY_ALICE;
        PGPSecretKey pgp_pri(in_pri);
        std::string message = decrypt_pka(pgp_pri, pgp, PASSPHRASE, false);
        EXPECT_EQ(message, "The magic words are squeamish ossifrage\n");
    }
}

TEST(PGPTest, test_gpg_clearsign) {

    std::string in = GPG_CLEARSIGN_ALICE;
    PGPCleartextSignature pgp(in);

    EXPECT_EQ(pgp.get_message(), "The magic words are squeamish ossifrage");

    auto key = pgp.get_sig();
    auto packets = key.get_packets();

    EXPECT_EQ(packets.size(), 1);

    Packet::Ptr p0 = packets[0];
    ASSERT_EQ(p0->get_tag(), 2);

    Tag2::Ptr tag2 = std::dynamic_pointer_cast<Tag2>(p0);

    EXPECT_EQ(tag2->get_version(), 4);

    EXPECT_EQ(tag2->get_size(), 284);

    EXPECT_EQ(tag2->get_pka(), 1);  // RSA
    EXPECT_EQ(tag2->get_hash(), 2); // SHA1
    EXPECT_EQ(tag2->get_left16(), "\x77\x8e");

    auto mpi = tag2->get_mpi();
    ASSERT_EQ(mpi.size(), 1);
    auto sign = mpi[0];
    EXPECT_EQ(bitsize(sign), 2047);
    EXPECT_EQ(mpitohex(sign), "4d1df9039259b42782d30c91e29ae9f7ac20e623e86c25e069ca441afc4a1cec30c9486c1a17799e8b1d39dcb8240b74269d083ad62f09232195fef84abca886c45f5263beaa02dde4b0a3ea4ff659d3bcaab5509a9d265e6326d560f8d0662ec07347fbf360e2421f851f12d923ceac84139245747ef3180b836eb4785428c9ea6fe5842e56d6ba7582b278b5ca68ad6bcb7a630568f800517264ddce690c96ab5925603be83b55207df45483c9cf57f88556e5a806910fb213e5cb3ee02bc45e4e4a894ebaec6967555cfae7615657a239a4523f56d0e399ccd35118d2b4daca2180b0fe24d8d258c59f8203dcb8579f8980802321ab274992bcf23d9d0095");

    // hashed
    {
        auto hashed = tag2->get_hashed_subpackets();
        ASSERT_EQ(hashed.size(), 1);

        Subpacket::Ptr s0 = hashed[0];
        ASSERT_EQ(s0->get_type(), 2);

        Tag2Sub2::Ptr sub2 = std::dynamic_pointer_cast<Tag2Sub2>(s0);
        EXPECT_EQ(sub2->get_time(), get_utc(2014, 06, 22, 13, 05, 41));
    }
    // unhashed
    {
        auto unhashed = tag2->get_unhashed_subpackets();
        ASSERT_EQ(unhashed.size(), 1);

        Subpacket::Ptr s0 = unhashed[0];
        ASSERT_EQ(s0->get_type(), 16);

        Tag2Sub16::Ptr sub16 = std::dynamic_pointer_cast<Tag2Sub16>(s0);
        EXPECT_EQ(sub16->get_keyid(), "\xd5\xd7\xda\x71\xc3\x54\x96\x0e");
    }

}

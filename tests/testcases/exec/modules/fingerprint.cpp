#include <sstream>

#include <gtest/gtest.h>

#include "exec/modules/fingerprint.h"
#include "../../testvectors/read_pgp.h"

TEST(Module, fingerprint){
    // default arguments
    {
        int argc = 1;
        char * argv[] = {(char *) (GPG_DIR "Alicepri")};
        std::stringstream out, err;

        ASSERT_EQ(module::fingerprint.get_name(), "fingerprint");
        ASSERT_EQ(module::fingerprint(argc, argv, out, err), 0);

        EXPECT_EQ(out.str(), "4b:32:92:e9:56:b5:77:ad:70:34:43:f4:d5:d7:da:71:c3:54:96:0e\n");
    }

    // set separator to space
    {
        int argc = 3;
        char * argv[] = {(char *) (GPG_DIR "Alicepri"), (char *) "-s", (char *) " "};
        std::stringstream out, err;

        ASSERT_EQ(module::fingerprint.get_name(), "fingerprint");
        ASSERT_EQ(module::fingerprint(argc, argv, out, err), 0);

        EXPECT_EQ(out.str(), "4b 32 92 e9 56 b5 77 ad 70 34 43 f4 d5 d7 da 71 c3 54 96 0e\n");
    }

    // set group size to 2 octets
    {
        int argc = 3;
        char * argv[] = {(char *) (GPG_DIR "Alicepri"), (char *) "-g", (char *) "2"};
        std::stringstream out, err;

        ASSERT_EQ(module::fingerprint.get_name(), "fingerprint");
        ASSERT_EQ(module::fingerprint(argc, argv, out, err), 0);

        EXPECT_EQ(out.str(), "4b32:92e9:56b5:77ad:7034:43f4:d5d7:da71:c354:960e\n");
    }

    // set group size to 3 octets
    {
        int argc = 3;
        char * argv[] = {(char *) (GPG_DIR "Alicepri"), (char *) "-g", (char *) "3"};
        std::stringstream out, err;

        ASSERT_EQ(module::fingerprint.get_name(), "fingerprint");
        ASSERT_EQ(module::fingerprint(argc, argv, out, err), 0);

        EXPECT_EQ(out.str(), "4b3292:e956b5:77ad70:3443f4:d5d7da:71c354:960e\n");
    }

    // set both separator and group size
    {
        int argc = 5;
        char * argv[] = {(char *) (GPG_DIR "Alicepri"), (char *) "-s", (char *) "::", (char *) "-g", (char *) "2"};
        std::stringstream out, err;

        ASSERT_EQ(module::fingerprint.get_name(), "fingerprint");
        ASSERT_EQ(module::fingerprint(argc, argv, out, err), 0);

        EXPECT_EQ(out.str(), "4b32::92e9::56b5::77ad::7034::43f4::d5d7::da71::c354::960e\n");
    }
}
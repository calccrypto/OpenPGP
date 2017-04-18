#include <sstream>

#include <gtest/gtest.h>

#include "exec/modules/show.h"
#include "../../testvectors/read_pgp.h"

TEST(Module, show){
    int argc = 1;
    char * argv[] = {(char *) (GPG_DIR "Alicepri")};
    std::stringstream out, err;

    ASSERT_EQ(module::show.get_name(), "show");
    ASSERT_EQ(module::show(argc, argv, out, err), 0);

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    EXPECT_EQ(out.str(), pri.show());
}
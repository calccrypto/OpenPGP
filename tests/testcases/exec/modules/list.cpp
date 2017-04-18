#include <sstream>

#include <gtest/gtest.h>

#include "exec/modules/list.h"
#include "../../testvectors/read_pgp.h"

TEST(Module, list){
    int argc = 1;
    char * argv[] = {(char *) (GPG_DIR "Alicepri")};
    std::stringstream out, err;

    ASSERT_EQ(module::list.get_name(), "list");
    ASSERT_EQ(module::list(argc, argv, out, err), 0);

    PGPSecretKey pri;
    ASSERT_EQ(read_pgp <PGPSecretKey> ("Alicepri", pri), true);

    EXPECT_EQ(out.str(), pri.list_keys());
}
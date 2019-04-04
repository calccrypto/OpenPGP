#include <gtest/gtest.h>

#include "DetachedSignature.h"
#include "pgp_macro.h"

TEST(DetachedSignature, detached) {
    TEST_PGP(OpenPGP::DetachedSignature, "tests/testvectors/gpg/detached");
}

#include <gtest/gtest.h>

#include "RevocationCertificate.h"
#include "pgp_macro.h"

TEST(RevocationCertificate, revoke) {
    TEST_PGP(OpenPGP::RevocationCertificate, "tests/testvectors/gpg/revoke");
}

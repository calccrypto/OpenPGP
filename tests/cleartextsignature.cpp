#include <gtest/gtest.h>

#include <fstream>

#include "CleartextSignature.h"

TEST(CleartextSignature, clearsign) {
    std::ifstream file("tests/testvectors/gpg/clearsign");
    ASSERT_TRUE(file);

    const std::string orig(std::istreambuf_iterator <char> (file), {});
    file.seekg(0);

    OpenPGP::CleartextSignature msg(file);
    OpenPGP::CleartextSignature copy(msg);

    EXPECT_EQ(copy.write(), trim_whitespace(orig, true, true));
    EXPECT_NO_THROW(copy.show());
}

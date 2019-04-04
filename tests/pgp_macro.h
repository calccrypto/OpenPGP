#ifndef __TEST_PGP_MACRO__
#define __TEST_PGP_MACRO__

#include <fstream>
#include <string>

#include <gtest/gtest.h>

#include "OpenPGP.h"

#define TEST_PGP(type, path)                                                              \
    std::ifstream file(path);                                                             \
    ASSERT_TRUE(file);                                                                    \
                                                                                          \
    const std::string orig(std::istreambuf_iterator <char> (file), {});                   \
    file.seekg(0);                                                                        \
                                                                                          \
    type msg(file);                                                                       \
    type copy((OpenPGP::PGP) msg);                                                        \
                                                                                          \
    EXPECT_EQ(copy.write(OpenPGP::PGP::Armored::YES), trim_whitespace(orig, true, true)); \
    EXPECT_NO_THROW(copy.show());

#endif

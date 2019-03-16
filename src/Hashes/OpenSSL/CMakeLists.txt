cmake_minimum_required(VERSION 3.6.0)

if (USE_OPENSSL)
    add_library(HashAlgs OBJECT
        MD5.cpp
        RIPEMD160.cpp
        SHA1.cpp
        SHA224.cpp
        SHA256.cpp
        SHA384.cpp
        SHA512.cpp)

    set_property(TARGET HashAlgs PROPERTY POSITION_INDEPENDENT_CODE ON)
endif()
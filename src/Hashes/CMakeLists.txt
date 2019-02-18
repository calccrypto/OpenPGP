cmake_minimum_required(VERSION 3.2.0)

add_library(Hashes OBJECT
    Hashes.cpp
    HashAlg.cpp
    MerkleDamgard.cpp
    MD5.cpp
    RIPEMD160.cpp
    SHA1.cpp
    SHA224.cpp
    SHA256.cpp
    SHA2_Functions.cpp
    SHA384.cpp
    SHA512.cpp)

set_property(TARGET Hashes PROPERTY POSITION_INDEPENDENT_CODE ON)
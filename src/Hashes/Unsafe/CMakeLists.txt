cmake_minimum_required(VERSION 3.6.0)

add_library(HashAlgs OBJECT
    MD5.cpp
    RIPEMD160.cpp
    SHA1.cpp
    SHA224.cpp
    SHA256.cpp
    SHA2_Functions.cpp
    SHA384.cpp
    SHA512.cpp)

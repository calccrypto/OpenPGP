cmake_minimum_required(VERSION 3.6.0)

add_library(HashTests OBJECT
    md5.cpp
    ripemd160.cpp
    sha1.cpp
    sha224.cpp
    sha256.cpp
    sha384.cpp
    sha512.cpp)

file(COPY testvectors DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

cmake_minimum_required(VERSION 3.0.0)

add_library(EncryptionTests OBJECT
    aes.cpp
    blowfish.cpp
    camellia.cpp
    cast128.cpp
    des.cpp
    idea.cpp
    tripledes.cpp
    twofish.cpp
)

file(COPY testvectors DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
cmake_minimum_required(VERSION 3.2.0)

add_library(Encryptions OBJECT
    SymAlg.cpp
    Encryptions.cpp
    AES.cpp
    Blowfish.cpp
    Camellia.cpp
    CAST128.cpp
    DES.cpp
    IDEA.cpp
    TDES.cpp
    Twofish.cpp)

set_property(TARGET Encryptions PROPERTY POSITION_INDEPENDENT_CODE ON)
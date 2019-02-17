cmake_minimum_required(VERSION 3.0.0)

add_subdirectory(common)
add_subdirectory(Compress)
add_subdirectory(Encryptions)
add_subdirectory(exec)
add_subdirectory(Hashes)
add_subdirectory(Misc)
add_subdirectory(Packets)
add_subdirectory(PKA)
add_subdirectory(RNG)
add_subdirectory(Subpackets)

add_library(TopLevel OBJECT
    CleartextSignature.cpp
    DetachedSignature.cpp
    Key.cpp
    Message.cpp
    PGP.cpp
    RevocationCertificate.cpp
    decrypt.cpp
    encrypt.cpp
    keygen.cpp
    revoke.cpp
    sign.cpp
    verify.cpp)

set_property(TARGET TopLevel PROPERTY POSITION_INDEPENDENT_CODE ON)
cmake_minimum_required(VERSION 3.6.0)

add_library(Hashes OBJECT
    Hashes.cpp
    Alg.cpp
    MerkleDamgard.cpp
)

set_property(TARGET Hashes PROPERTY POSITION_INDEPENDENT_CODE ON)

if (USE_OPENSS_HASH)
    add_subdirectory(OpenSSL)
else()
    add_subdirectory(Unsafe)
endif()

set_property(TARGET HashAlgs PROPERTY POSITION_INDEPENDENT_CODE ON)

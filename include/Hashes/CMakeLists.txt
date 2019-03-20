cmake_minimum_required(VERSION 3.6.0)

install(FILES
    Alg.h
    Hashes.h
    MerkleDamgard.h
    DESTINATION include/Hashes)

if (USE_OPENSSL_HASH)
    add_subdirectory(OpenSSL)
else()
    add_subdirectory(Unsafe)
endif()

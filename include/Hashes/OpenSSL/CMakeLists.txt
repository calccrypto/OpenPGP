cmake_minimum_required(VERSION 3.6.0)

if (USE_OPENSSL)
    install(FILES
        MD5.h
        RIPEMD160.h
        SHA1.h
        SHA224.h
        SHA256.h
        SHA384.h
        SHA512.h

        DESTINATION include/Hashes)
endif()
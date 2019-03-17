cmake_minimum_required(VERSION 3.6.0)

set(RNG_HEADERS
    BBS.h
    RNGs.h)

if (USE_OPENSSL)
    set(RNG_HEADERS
        ${RNG_HEADERS}
        RAND_bytes.h)
endif()

install(FILES
    ${RNG_HEADERS}
    DESTINATION include/RNG)

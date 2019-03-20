cmake_minimum_required(VERSION 3.6.0)

set(RNG_HEADERS
    RNGs.h)

if (USE_OPENSSL_RNG)
    set(RNG_HEADERS
        ${RNG_HEADERS}
        RAND_bytes.h)
else()
    set(RNG_HEADERS
        ${RNG_HEADERS}
        BBS.h)
endif()

install(FILES
    ${RNG_HEADERS}
    DESTINATION include/RNG)

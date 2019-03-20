cmake_minimum_required(VERSION 3.6.0)

set(RNG_SOURCES)

if (USE_OPENSSL_RNG)
   set(RNG_SOURCES
       ${RNG_SOURCES}
       RAND_bytes.cpp)
else()
   set(RNG_SOURCES
       ${RNG_SOURCES}
       BBS.cpp)
endif()

add_library(RNG OBJECT
    ${RNG_SOURCES})

set_property(TARGET RNG PROPERTY POSITION_INDEPENDENT_CODE ON)

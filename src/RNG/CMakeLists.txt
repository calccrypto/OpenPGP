cmake_minimum_required(VERSION 3.6.0)

set(RNG_SOURCES
    BBS.cpp
)

if (USE_OPENSSL)
   set(RNG_SOURCES
       ${RNG_SOURCES}
       RAND_bytes.cpp)
endif()

add_library(RNG OBJECT
    ${RNG_SOURCES})

set_property(TARGET RNG PROPERTY POSITION_INDEPENDENT_CODE ON)

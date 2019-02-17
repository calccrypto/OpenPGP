cmake_minimum_required(VERSION 3.0.0)

add_library(Compress OBJECT
    Compress.cpp
    pgpbzip2.cpp
    pgpzlib.cpp)

set_property(TARGET Compress PROPERTY POSITION_INDEPENDENT_CODE ON)
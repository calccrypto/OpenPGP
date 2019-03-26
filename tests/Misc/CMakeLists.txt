cmake_minimum_required(VERSION 3.6.0)

add_library(MiscTests OBJECT
    Length.cpp
    mpi.cpp
    pgptime.cpp
    radix64.cpp
    s2k.cpp)

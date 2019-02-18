cmake_minimum_required(VERSION 3.2.0)

add_library(Misc OBJECT
    cfb.cpp
    CRC-24.cpp
    mpi.cpp
    pgptime.cpp
    PKCS1.cpp
    radix64.cpp
    s2k.cpp
    sigcalc.cpp
    sigtypes.cpp)
    
set_property(TARGET Misc PROPERTY POSITION_INDEPENDENT_CODE ON)
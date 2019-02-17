cmake_minimum_required(VERSION 3.0.0)

add_library(PKA OBJECT
    PKAs.cpp
    DSA.cpp
    ElGamal.cpp
    RSA.cpp)

set_property(TARGET PKA PROPERTY POSITION_INDEPENDENT_CODE ON)
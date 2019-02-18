cmake_minimum_required(VERSION 3.2.0)

add_library(PKATests OBJECT
    dsa.cpp
    rsa.cpp)

file(COPY testvectors DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
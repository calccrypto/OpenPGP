cmake_minimum_required(VERSION 3.2.0)

add_library(RNG OBJECT
    BBS.cpp)

set_property(TARGET RNG PROPERTY POSITION_INDEPENDENT_CODE ON)
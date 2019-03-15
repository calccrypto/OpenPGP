cmake_minimum_required(VERSION 3.6.0)

add_library(common OBJECT
    HumanReadable.cpp
    includes.cpp)

set_property(TARGET common PROPERTY POSITION_INDEPENDENT_CODE ON)

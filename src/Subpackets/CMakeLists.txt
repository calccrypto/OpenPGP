cmake_minimum_required(VERSION 3.2.0)

add_subdirectory(Tag2)
add_subdirectory(Tag17)

add_library(Subpackets OBJECT
    Subpacket.cpp)

set_property(TARGET Subpackets PROPERTY POSITION_INDEPENDENT_CODE ON)
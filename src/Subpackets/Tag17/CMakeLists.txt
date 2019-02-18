cmake_minimum_required(VERSION 3.2.0)

add_library(Tag17Subpackets OBJECT
    Subpacket.cpp
    Sub1.cpp)

set_property(TARGET Tag17Subpackets PROPERTY POSITION_INDEPENDENT_CODE ON)
cmake_minimum_required(VERSION 3.6.0)

add_library(Packets OBJECT
    Packet.cpp
    Partial.cpp
    Key.cpp
    User.cpp
    Tag0.cpp
    Tag1.cpp
    Tag2.cpp
    Tag3.cpp
    Tag4.cpp
    Tag5.cpp
    Tag6.cpp
    Tag7.cpp
    Tag8.cpp
    Tag9.cpp
    Tag10.cpp
    Tag11.cpp
    Tag12.cpp
    Tag13.cpp
    Tag14.cpp
    Tag17.cpp
    Tag18.cpp
    Tag19.cpp
    Tag60.cpp
    Tag61.cpp
    Tag62.cpp
    Tag63.cpp

    Subpacket.cpp)

set_property(TARGET Packets PROPERTY POSITION_INDEPENDENT_CODE ON)

add_subdirectory(Tag2)
add_subdirectory(Tag17)

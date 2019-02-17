cmake_minimum_required(VERSION 3.0.0)

add_subdirectory(Tag2)
add_subdirectory(Tag17)

install(FILES
    Subpacket.h
    Subpackets.h

    DESTINATION include/PKA)
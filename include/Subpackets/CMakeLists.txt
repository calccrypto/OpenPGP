cmake_minimum_required(VERSION 3.6.0)

add_subdirectory(Tag2)
add_subdirectory(Tag17)

install(FILES
    Subpacket.h
    Subpackets.h

    DESTINATION include/Subpackets)

cmake_minimum_required(VERSION 3.6.0)

install(FILES
    Key.h
    Packet.h
    Packets.h
    Partial.h
    PartialBodyLengthEnums.h
    Tag0.h
    Tag10.h
    Tag11.h
    Tag12.h
    Tag13.h
    Tag14.h
    Tag17.h
    Tag18.h
    Tag19.h
    Tag1.h
    Tag2.h
    Tag3.h
    Tag4.h
    Tag5.h
    Tag60.h
    Tag61.h
    Tag62.h
    Tag63.h
    Tag6.h
    Tag7.h
    Tag8.h
    Tag9.h
    User.h

    Subpacket.h

    DESTINATION include/Packets)

add_subdirectory(Tag2)
add_subdirectory(Tag17)

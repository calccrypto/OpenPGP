OpenPGP in C++
by Jason Lee @ calccrypto at gmail.com

With much help from:
    Alex Stapleton (OpenPGP-SDK)
    Auston Sterling - Massive amounts of debugging and programming help
    Jon Callas (RFC 4880)
    Herbert Hanewinkel
    Many people on the StackExchange network
    pgpdump.net
    PortablePGP

IMPORTANT:
    This library was not written for actual use.
    Rather, it was meant for educational purposes,
    so if you choose to use it in a real setting
    where secrecy is requied, do so at your own risk.
    People who use this library to learn about the
    internals of PGP can easily use/add a few std::couts
    to see the internal workings.

This is a C++ implementation of the majority of RFC 4880,
the OpenPGP Message Format. All the necessary files were
written from scratch by me, with some assistance. No outside
libraries are necessary. This may change if I decide to add
compression algorithms.

The purpose of this library is to help clear up the mess that
is RFC 4880. It is extremely vague at best, and it took me
years to figure out most of it. No one should have to go
through that. However, knowing how PGP is structured is still
good to know.

This library allows for the modification of PGP packets, such
as providing incorrect checksums and public key values. That
was done on purpose. I used it to test keys I created with
known working values. What others do with this capability
is none of my concern or responsibility.

This library should be relatively straightforwards to use:
Simply #include "OpenPGP.h" for the data types, and whatever
functions needed, such as encrypt (#include "encrypt.h") and
decrypt (#include "decrypt.h").

The main.cpp provides a simple text-based user interface, which
can be used as examples on how to use the functions. A lot of the
output was based on/inspired by pgpdump.net and GPG.

The main data types PGP, Packet, Subpacket, and S2K have the
four standard functions: read, show, raw, and write.
    read  - reads data without the respective headers
            (packet::read(std::string) takes in packet
            data without its header or length).

    show  - displays the data in human readable form
            like the way pgpdump.net does it.

    raw   - returns a string that can be read by the
            read function.

    write - returns a string of the entire data,
            including extra data, such as header
            and size.

To build:

    make

	or

	g++ -std=c++11 *.cpp */*.cpp

	or some equivalent.

	C++11 is necessary.

To run:
    ./OpenPGP

Notes:
    Key generation does not really work. Even if the code were
    to be completed, the generation of PKA values takes forever.

    Keyrings were not implemented.

    There are some things that are not implemented, such as
    the Twofish algorithm and compression/decompression of data.

    There are also serveral untested functions, having never
    encountered real versions of those packets/subpackets.

    Data is encrypted and decrypted without compression, since
    compression/decompression algorithms were not implemented.
    This program most likely cannot return "correct" using
    data from programs that compress their encrypted data, such
    as Bouncy Castle and GPG. Although the data will be correctly
    decrypted, it will not be decompressed.

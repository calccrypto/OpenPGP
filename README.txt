OpenPGP in C++
Copyright (c) 2013 Jason Lee @ calccrypto at gmail.com

Please see LICENSE file for license.

With much help from:
    Alex Stapleton (OpenPGP-SDK)
    Auston Sterling - Massive amounts of debugging and programming help
    Jon Callas (RFC 4880)
    Herbert Hanewinkel (hanewin.net)
    Many people on the StackExchange network
    pgpdump.net
    PortablePGP

IMPORTANT:
    This library was not written for actual use.
    Rather, it was meant for learning about the
    internals of PGP can easily use/add a few 
    std::couts to see the internal workings.
    So if you choose to use it in a real setting 
    where secrecy is required, do so at your own 
    risk.
    
This is a C++ implementation of the majority of RFC 4880,
the OpenPGP Message Format. In addition to the included files,
the GNU Multiprecision Library is necessary (gmp.org,
sudo apt-get install libdev-gmp, or equivalent).

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

This library should be relatively straightforward to use:
Simply #include whatever functions needed:
    key generation - generatekey.h
    key revokation - revoke.h
    encrypt        - encrypt.h
    decrypt        - decrypt.h
    sign           - sign.h
    verify         - verify.h

The exec/main.cpp file provides a simple command line interface,
which can be used as examples on how to use the functions. A lot 
of the output was based on/inspired by pgpdump.net and GPG.

The data types have some standard functions:
    read  - reads data without the respective
            header information

    show  - displays the data in human readable form
            like the way pgpdump.net does it.

    raw   - returns a string that can be read by the
            read function.

    write - returns a string of the entire data,
            including extra data, such as header
            and size.

    clone - returns a pointer to a deep copy of
            the object (mainly used for moving
            PGP data around).

Operator= and the copy constructor have been overloaded
for the data structures that need deep copy.

To build the command line program:
    Use the Code::Blocks project file

    or

    make

    or

    (from OpenPGP directory)
    g++ -std=c++11 -Wall */*.cpp *.cpp -lgmpxx -lgmp

    or some equivalent.

When building for another project, remember to link GMP to
the main program.

Notes:
    Keyrings were not implemented.

    There are some things that are not implemented, such as
    the Twofish algorithm and compression/decompression of data.
    If someone would be willing to work on that part, it would
    be much appreciated.

    There are also several untested functions, having never
    encountered real versions of those packets/subpackets.

    Although data is properly encrypted and decrypted, data
    from other PGP sources such as Bouncy Castle and GPG will
    most likely not be able to decrypt "properly" since most
    PGP implementations compress the data before encrypting, but
    not this one (yet).

    If for some reason the program cannot operate on some data
    properly, the entire program will crash through the exit function.

# OpenPGP in C++

Copyright (c) 2013 - 2018 Jason Lee @ calccrypto at gmail.com

Please see [LICENSE](LICENSE) file for the license.

Also:
 - cmake/FindGMP.cmake is by Jack Poulson from [Elemental](https://github.com/elemental/Elemental) and is licened under the BSD License. It was changed slightly to remove a debug message.
 - Some of CMakeLists.txt was taken from the [Kitware CMake wiki RPath handling page](https://gitlab.kitware.com/cmake/community/wikis/doc/cmake/RPATH-handling#always-full-rpath).

[![Build Status](https://travis-ci.org/calccrypto/OpenPGP.svg?branch=master)](https://travis-ci.org/calccrypto/OpenPGP)

### With much help from

- Alex Stapleton (OpenPGP-SDK)
- Auston Sterling - Massive amounts of debugging and programming help
- D-o-c Key merging and elliptic curve parsing
- Jon Callas (RFC 4880)
- Herbert Hanewinkel (hanewin.net)
- Many people on the StackExchange network
- mugwort-rc - Tons of testing code, code style updates, and bugfixes
- pgpdump.net
- PortablePGP

## IMPORTANT

**This library was not written for actual use.**

**Rather, it was meant for learning about the**
**internals of PGP can easily use/add a few**
**`std::cout`s to see the internal workings.**

**So if you choose to use it in a real setting**
**where secrecy is required, do so at your own**
**risk.**

--------------------------------------------------------------------------------

This is a C++ implementation of the majority of RFC 4880,
the OpenPGP Message Format.

The purpose of this library is to help clear up the mess that
is RFC 4880. It is extremely vague at best, and it took me
a long time to figure out most of it. No one should have to go
through that. However, knowing how PGP is structured is still
good to know.

This library allows for the modification of PGP packets, such
as providing incorrect checksums and public key values. That
was done on purpose. I used it to test keys I created with
known working values. What others do with this capability
is none of my concern or responsibility.

## Building

### Tools
- A C++ compiler with C++11 support
- CMake 3

### Libraries
- GMP (<https://gmplib.org/>)
- bzip2 (<http://www.bzip.org/>)
- zlib (<http://www.zlib.net/>)

### Build
```bash
mkdir build
cd build
cmake -DCMAKE_INSTALL_PREFIX=<prefix> -DGPG_COMPATIBLE=<True/False> ..
make
<make test>
make install
```

The GPG_COMPATIBLE flag is used to make this library gpg compatible
when gpg does not follow the standard. By default this is set to False.

## Usage

This library should be relatively straightforward to use: Simply `#include "OpenPGP.h"`.

If you do not wish to include everything at once, `#include` whatever functions are needed:

 Feature        | Header         | Namespace
----------------|----------------|------------------
 key generation | keygen.h       | OpenPGP::KeyGen
 key revocation | revoke.h       | OpenPGP::Revoke
 encrypt        | encrypt.h      | OpenPGP::Encrypt
 decrypt        | decrypt.h      | OpenPGP::Decrypt
 sign           | sign.h         | OpenPGP::Sign
 verify         | verify.h       | OpenPGP::Verify

Multiple classes inherit from the abstract base class `PGP` in order
to make differentiating PGP block types better in code:

 PGP block type        | Description
-----------------------|-------------------------------------
 DetachedSignature     | detached signatures for files
 Key                   | base class for OpenPGP key types
 PublicKey             | holds public keys; inherits Key
 SecretKey             | holds private keys; inherits Key
 Message               | holds OpenPGP Messages
 RevocationCertificate | holds revocation certificates

All these different types are able to read in any PGP data, but
will cause problems when used. The `meaningful` function in these
PGP objects is provided to make sure that the data contained is
meaningful.

`CleartextSignature` does not inherit from PGP and cannot
read non-Cleartext Signature data.

All data structures have some standard functions:

Function | Description
---------|------------------------------------------
   read  | reads data without the header information
   show  | displays the data in human readable form like the way pgpdump.net does it.
   raw   | returns a string of packet data without the header information
   write | returns a string of the entire data, including the header.
   clone | returns a pointer to a deep copy of the object (mainly used for moving PGP data around).
   Ptr   | a typedef for std::shared_ptr&lt;T&gt; for the class where the typedef is found.

`operator=` and the copy constructor have been overloaded
for the data structures that need deep copy.

### Command Line Interface
The `exec/main.cpp` file provides a simple command line tool that
uses modules from the exec/modules directory to provide functionality.
These can be used as examples on how to use the functions. A lot
of the output was based on/inspired by pgpdump.net and GPG.

## Notes:

Keyrings were not implemented. Rather, individual keys are
read from the directory used as arguments to functions.

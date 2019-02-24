cmake_minimum_required(VERSION 3.6.0)

add_subdirectory(common)
add_subdirectory(Compress)
add_subdirectory(Encryptions)
add_subdirectory(Hashes)
add_subdirectory(Misc)
add_subdirectory(Packets)
add_subdirectory(PKA)
add_subdirectory(RNG)

install(FILES
    # main header file
    OpenPGP.h

    # OpenPGP Types
    CleartextSignature.h
    DetachedSignature.h
    Key.h
    Message.h
    PGP.h
    RevocationCertificate.h

    # OpenPGP Functions
    decrypt.h
    encrypt.h
    keygen.h
    revoke.h
    sign.h
    verify.h

    DESTINATION include)

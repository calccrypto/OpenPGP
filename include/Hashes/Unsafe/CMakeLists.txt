cmake_minimum_required(VERSION 3.6.0)

install(FILES
    MD5_Const.h
    MD5.h
    RIPEMD160_Const.h
    RIPEMD160.h
    RIPEMD_Const.h
    SHA1.h
    SHA224.h
    SHA256_Const.h
    SHA256.h
    SHA2_Functions.h
    SHA384.h
    SHA512_Const.h
    SHA512.h

    DESTINATION include/Hashes)

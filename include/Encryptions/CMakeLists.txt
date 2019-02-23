cmake_minimum_required(VERSION 3.6.0)

install(FILES
    AES_Const.h
    AES.h
    Blowfish_Const.h
    Blowfish.h
    Camellia_Const.h
    Camellia.h
    CAST128_Const.h
    CAST128.h
    CAST_Const.h
    DES_Const.h
    DES.h
    Encryptions.h
    IDEA.h
    SymAlg.h
    TDES.h
    Twofish_Const.h
    Twofish.h

    DESTINATION include/Encryptions)

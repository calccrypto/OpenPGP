cmake_minimum_required(VERSION 3.6.0)

install(FILES
    cfb.h
    CRC-24.h
    mpi.h
    pgptime.h
    PKCS1.h
    radix64.h
    s2k.h
    sigcalc.h
    sigtypes.h

    DESTINATION include/Misc)

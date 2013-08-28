#include "mpi.h"

// given some value, return the formatted mpi
std::string write_MPI(integer data){
    return unhexlify(makehex(data.bits(), 4)) + data.str(256);
}

// remove mpi from data, returning mpi value. the rest of the data will be returned through pass-by-reference
integer read_MPI(std::string & data){
    uint16_t size = (((uint8_t) data[0]) << 8) + (uint8_t) data[1];                 // get bits
    while (size & 7){
        size++;                                                                     // pad to nearest byte
    }
    size >>= 3;                                                                     // get number of bytes
    integer out(data.substr(2, size), 256);                                         // turn to integer
    data = data.substr(2 + size, data.size() - 2 - size);                           // remove mpi from data
    return out;
}


#include "mpi.h"

// given some value, return the formatted mpi
std::string write_MPI(mpz_class data){
    std::string out = data.get_str(16);
    out = std::string(out.size() & 1, '0') + out;
    out = makehex(makebin(data).size(), 4) + out;
    return unhexlify(out);
}

// remove mpi from data, returning mpi value. the rest of the data will be returned through pass-by-reference
mpz_class read_MPI(std::string & data){
    uint16_t size = (((uint8_t) data[0]) << 8) + (uint8_t) data[1];                 // get bits
    while (size & 7){
        size++;                                                                     // pad to nearest byte
    }
    size >>= 3;                                                                     // get number of bytes
    mpz_class out(hexlify(data.substr(2, size)), 16);                               // turn to mpz_class
    data = data.substr(2 + size, data.size() - 2 - size);                           // remove mpi from data
    return out;
}


#include "mpi.h"

// given some value, return the formatted mpi
std::string write_MPI(const mpz_class & data){
    std::string out = data.get_str(16);
    out = ((out.size() & 1)?"0":"") + out;
    out = makehex(data.get_str(2).size(), 4) + out;
    return unhexlify(out);
}

// remove mpi from data, returning mpi value. the rest of the data will be returned through pass-by-reference
mpz_class read_MPI(std::string & data){
    uint16_t size = (static_cast <uint8_t> (data[0]) << 8) + static_cast <uint8_t> (data[1]);                 // get bits
    while (size & 7){
        size++;                                                                     // pad to nearest byte
    }
    size >>= 3;                                                                     // get number of octets
    mpz_class out(hexlify(data.substr(2, size)), 16);                               // turn to mpz_class
    data = data.substr(2 + size, data.size() - 2 - size);                           // remove mpi from data
    return out;
}


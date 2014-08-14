#include "mpi.h"

#include "RNG/BBS.h"

PGPMPI hextompi(const std::string & hex){
    return PGPMPI(hex, 16);
}

PGPMPI dectompi(const std::string & dec){
    return PGPMPI(dec, 10);
}

PGPMPI bintompi(const std::string & bin){
    return PGPMPI(bin, 2);
}

PGPMPI rawtompi(const std::string & raw){
    return hextompi(hexlify(raw));
}

std::string mpitohex(const PGPMPI & a){
    std::string out = a.get_str(16);
    if (out.size() % 2 == 1){
        out = "0" + out;
    }
    return out;
}

std::string mpitodec(const PGPMPI & a){
    return a.get_str(10);
}

std::string mpitobin(const PGPMPI & a){
    return a.get_str(2);
}

std::string mpitoraw(const PGPMPI & a){
    return unhexlify(mpitohex(a));
}

unsigned long mpitoulong(const PGPMPI & a){
    return a.get_ui();
}

unsigned int bitsize(const PGPMPI &a){
    return mpitobin(a).size();
}

bool knuth_prime_test(const PGPMPI & a, int test){
    return mpz_probab_prime_p(a.get_mpz_t(), test);
}

PGPMPI mpigcd(const PGPMPI &a, const PGPMPI &b){
    PGPMPI ret;
    mpz_gcd(ret.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t());
    return ret;
}
PGPMPI nextprime(const PGPMPI &a){
    PGPMPI ret;
    mpz_nextprime(ret.get_mpz_t(), a.get_mpz_t());
    return ret;
}
PGPMPI powm(const PGPMPI &base, const PGPMPI &exp, const PGPMPI &mod){
    PGPMPI ret;
    mpz_powm_sec(ret.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
    return ret;
}
PGPMPI invert(const PGPMPI &a, const PGPMPI &b){
    PGPMPI ret;
    mpz_invert(ret.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t());
    return ret;
}

PGPMPI random(unsigned int bits){
    try{
        return bintompi(BBS().rand(bits));
    } catch (...) {
        BBS(static_cast <PGPMPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded
        return bintompi(BBS().rand(bits));
    }
}

// given some value, return the formatted mpi
std::string write_MPI(const PGPMPI & data){
    std::string out = mpitoraw(data);
    return unhexlify(makehex(bitsize(data), 4)) + out;
}

// remove mpi from data, returning mpi value. the rest of the data will be returned through pass-by-reference
PGPMPI read_MPI(std::string & data){
    uint16_t size = (static_cast <uint8_t> (data[0]) << 8) + static_cast <uint8_t> (data[1]); // get bits
    while (size & 7){
        size++;                                                                     // pad to nearest octet
    }
    size >>= 3;                                                                     // get number of octets
    PGPMPI out = rawtompi(data.substr(2, size));                                    // turn to mpz_class
    data = data.substr(2 + size, data.size() - 2 - size);                           // remove mpi from data
    return out;
}


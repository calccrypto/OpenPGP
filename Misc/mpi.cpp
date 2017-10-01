#include "mpi.h"

#include "../RNG/BBS.h"

namespace OpenPGP {

MPI hextompi(const std::string & hex){
    return MPI(hex, 16);
}

MPI dectompi(const std::string & dec){
    return MPI(dec, 10);
}

MPI bintompi(const std::string & bin){
    return MPI(bin, 2);
}

MPI rawtompi(const std::string & raw){
    return hextompi(hexlify(raw));
}

std::string mpitohex(const MPI & a){
    std::string out = a.get_str(16);
    if (out.size() % 2 == 1){
        out = "0" + out;
    }
    return out;
}

std::string mpitodec(const MPI & a){
    return a.get_str(10);
}

std::string mpitobin(const MPI & a){
    return a.get_str(2);
}

std::string mpitoraw(const MPI & a){
    return unhexlify(mpitohex(a));
}

unsigned long mpitoulong(const MPI & a){
    return a.get_ui();
}

std::size_t bitsize(const MPI &a){
    return mpitobin(a).size();
}

bool knuth_prime_test(const MPI & a, int test){
    return mpz_probab_prime_p(a.get_mpz_t(), test);
}

void mpiswap(MPI & a, MPI & b){
    std::swap(a, b);
}

MPI mpigcd(const MPI &a, const MPI &b){
    MPI ret;
    mpz_gcd(ret.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t());
    return ret;
}

MPI nextprime(const MPI &a){
    MPI ret;
    mpz_nextprime(ret.get_mpz_t(), a.get_mpz_t());
    return ret;
}

MPI powm(const MPI &base, const MPI &exp, const MPI &mod){
    MPI ret;
    mpz_powm_sec(ret.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
    return ret;
}

MPI invert(const MPI &a, const MPI &b){
    MPI ret;
    mpz_invert(ret.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t());
    return ret;
}

MPI random(unsigned int bits){
    try{
        return bintompi(RNG::BBS().rand(bits));
    } catch (...) {
        RNG::BBS(static_cast <MPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded
        return bintompi(RNG::BBS().rand(bits));
    }
}

// given some value, return the formatted mpi
std::string write_MPI(const MPI & data){
    const std::string out = mpitoraw(data);
    return unhexlify(makehex(bitsize(data), 4)) + out;
}

// Read mpi from data, returning mpi value. The position will be updated to the octet after the end of the mpi value
MPI read_MPI(const std::string & data, std::string::size_type & pos){
    // get number of bits
    uint16_t size = (static_cast <uint8_t> (data[pos]) << 8) |
                     static_cast <uint8_t> (data[pos + 1]);
    // update position
    pos += 2;

    // pad to nearest 8 bits
    while (size & 7){
        size++;
    }

    // get number of octets
    size >>= 3;

    // turn to mpz_class
    const MPI out = rawtompi(data.substr(pos, size));
    pos += size;
    return out;
}

}
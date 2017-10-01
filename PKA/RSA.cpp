#include "RSA.h"

namespace OpenPGP {
namespace PKA {
namespace RSA {

Values keygen(const uint32_t & bits){
    RNG::BBS(static_cast <MPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded

    MPI p = 3;
    MPI q = 3;

    #ifdef GPG_COMPATIBLE
    // gpg only accepts 'n's of certain sizes
    const uint32_t nbitsize = bits << 1;
    if ((nbitsize < 1024) ||    // less than 1024
        (nbitsize & 31)   ||    // not a multiple of 32
        (nbitsize > 4096)){     // more than 4096
        return {};
    }

    MPI n;
    while (true){
        p = nextprime(bintompi("1" + RNG::BBS().rand(bits - 1)));
        q = nextprime(bintompi("1" + RNG::BBS().rand(bits - 1)));
        n = p * q;

        const std::size_t nbits = bitsize(n);
        if ((nbits == nbitsize) || (nbits == (nbitsize - 8))){
            break;
        }
    }
    #else
    // don't check bitsize
    while (p == q){
        p = nextprime(bintompi(RNG::BBS().rand(bits)));
        q = nextprime(bintompi(RNG::BBS().rand(bits)));
    }
    const MPI n = p * q;
    #endif

    // required by RFC 4880 sec 5.5.3
    if (p > q){
        mpiswap(p, q);
    }

    const MPI tot = (p - 1) * (q - 1);

    MPI e = bintompi(RNG::BBS().rand(bits));
    e += ((e & 1) == 0);
    while (mpigcd(tot, e) != 1){
        e += 2;
    }

    // split this into {n, e} and {d, p, q, u}
    return {n, e, invert(e, tot), p, q, invert(p, q)};
}

MPI encrypt(const MPI & data, const Values & pub){
    return powm(data, pub[1], pub[0]);
}

MPI encrypt(const std::string & data, const Values & pub){
    return powm(rawtompi(data), pub[1], pub[0]);
}

MPI decrypt(const MPI & data, const Values & pri, const Values & pub){
    return powm(data, pri[0], pub[0]);
}

MPI sign(const MPI & data, const Values & pri, const Values & pub){
    return decrypt(data, pri, pub);
}

MPI sign(const std::string & data, const Values & pri, const Values & pub){
    return decrypt(rawtompi(data), pri, pub);
}

bool verify(const MPI & data, const Values & signature, const Values & pub){
    return (encrypt(signature[0], pub) == data);
}

bool verify(const std::string & data, const Values & signature, const Values & pub){
    return verify(rawtompi(data), signature, pub);
}

}
}
}
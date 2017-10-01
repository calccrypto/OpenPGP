#include "PKCS1.h"

namespace OpenPGP {

std::string EME_PKCS1v1_5_ENCODE(const std::string & m, const unsigned int & k){
    RNG::BBS(static_cast <MPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded
    if (m.size() > (k - 11)){
        // "Error: EME-PKCS1 Message too long.\n";
        return "";
    }

    std::string EM = zero + "\x02";
    while (EM.size() < k - m.size() - 1){
        unsigned char c = 0;
        for(uint8_t x = 0; x < 8; x++){
            c = (c << 1) | (RNG::BBS().rand(1) == "1");
        }

        if (c){ // non-zero octets only
            EM += std::string(1, c);
        }
    }

    return EM + zero + m;
}

std::string EME_PKCS1v1_5_DECODE(const std::string & m){
    if (m.size() > 11){
        if (!m[0]){
            if (m[1] == '\x02'){
                std::string::size_type x = 2;
                while ((x < m.size()) && m[x]){
                    x++;
                }
                return m.substr(x + 1, m.size() - x - 1);
            }
        }
    }

    // "Error: EME-PKCS1 Decryption Error.\n";
    return "";
}

std::string EMSA_PKCS1_v1_5(const uint8_t & hash, const std::string & hashed_data, const unsigned int & keylength){
    return zero + "\x01" + std::string(keylength - (Hash::ASN1_DER.at(hash).size() >> 1) - 3 - (Hash::LENGTH.at(hash) >> 3), 0xff) + zero + unhexlify(Hash::ASN1_DER.at(hash)) + hashed_data;
}

}
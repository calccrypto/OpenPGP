#include "PKCS1.h"

std::string EME_PKCS1v1_5_ENCODE(const std::string & m, const unsigned int & k){
    BBS(static_cast <PGPMPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded
    if (m.size() > (k - 11)){
        throw std::runtime_error("Error: EME-PKCS1 Message too long.");
    }
    std::string EM = zero + "\x02";
    while (EM.size() < k - m.size() - 1){
        unsigned char c = 0;
        for(uint8_t x = 0; x < 8; x++){
            c = (c << 1) | (BBS().rand(1) == "1");
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
            if (m[1] == 2){
                unsigned int x = 2;
                while (m[x]){
                    x++;
                }
                return m.substr(x + 1, m.size() - x - 1);
            }
        }
    }
    throw std::runtime_error("Error: EME-PKCS1 Decoding Error.");
}

std::string EMSA_PKCS1_v1_5(const uint8_t & h, const std::string & hashed_data, const unsigned int & keylength){
    return zero + "\x01" + std::string(keylength - (Hash_ASN1_DER.at(Hash_Algorithms.at(h)).size() >> 1) - 3 - (Hash_Length.at(Hash_Algorithms.at(h)) >> 3), 0xff) + zero + unhexlify(Hash_ASN1_DER.at(Hash_Algorithms.at(h))) + hashed_data;
}

#include "PKCS1.h"

std::string EME_PKCS1v1_5_ENCODE(const std::string & m, const unsigned int & k){
    BBS((mpz_class) (int) now()); // seed just in case not seeded
    if (m.size() > (k - 11)){
        std::cerr << "Error: EME-PKCS1 Message too long." << std::endl;
        exit(1);
    }
    std::string EM = zero + "\x02";
    for(unsigned int x = 0; x < k - m.size() - 3; x++){
        unsigned char c = 0;
        for(uint8_t y = 0; y < 8; y++){
            c = (c + (BBS().rand(1) == "1")) << 1;
        }
        EM += std::string(1, c);
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
    std::cerr << "Error: EME-PKCS1 Decryption Error." << std::endl;
    exit(1);
}

std::string EMSA_PKCS1_v1_5(const uint8_t & h, std::string & hashed_data, const unsigned int & keylength){
    return zero + "\x01" + std::string(keylength - (Hash_ASN1_DER.at(Hash_Algorithms.at(h)).size() >> 1) - 3 - (Hash_Length.at(Hash_Algorithms.at(h)) >> 3), 0xff) + zero + unhexlify(Hash_ASN1_DER.at(Hash_Algorithms.at(h))) + hashed_data;
}

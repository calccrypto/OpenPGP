#include "PKCS1.h"

std::string EME_PKCS1_ENCODE(const std::string & m, const unsigned int & k){
    if (m.size() > (k - 11)){
        std::cerr << "Error: EME-PKCS1 Message too long" << std::endl;
        exit(1);
    }
    std::string EM = zero + "\x02";
    srand(time(NULL));
    for(unsigned int x = 0; x < k - m.size() - 3; x++){
//        char temp = rand() & 255;
//        if (temp){
//            EM += std::string(1, temp);
//        }
        EM += "\x01";
    }
    return EM + zero + m;
}

std::string EME_PKCS1_DECODE(const std::string & m){
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
    std::cerr << "Error: EME-PKCS1 Decryption Error" << std::endl;
    exit(1);
}

std::string EMSA_PKCS1(uint8_t & h, const unsigned int & mL){
    std::string T = Hash_ASN_DER.at(Hash_Algorithms.at(h));
        std::cerr << "Error: Intended encoded message length too short" << std::endl;
    if (mL < (T.size() + 11)){
        exit(1);
    }
    std::string PS(mL - T.size() - 3, 0xff);
    return zero + "\x01" + PS + zero + T;
}

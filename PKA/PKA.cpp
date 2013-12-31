#include "PKA.h"
void generate_key_pair(const uint8_t pka, const std::vector <unsigned int> & param, std::vector <mpz_class> & pub, std::vector <mpz_class> & pri){
    std::vector <mpz_class> temp;
    switch (pka){
        case 1: case 2: case 3: // RSA
            temp = RSA_keygen(param[0]);
            pri = {temp[2]};
            temp.pop_back();
            pub = temp;
            break;
        case 16:                // ElGamal
            temp = ElGamal_keygen(param[0]);
            pri = {temp[2]};
            temp.pop_back();
            pub = temp;
            break;
        case 17:                // DSA
            pub = new_DSA_public(param[0], param[1]);
            pri = DSA_keygen(pub);
            break;
        default:
            std::cerr << "Error: Undefined or reserved PKA number: " << (int) pka<< std::endl;
            throw(1);
            break;
    }
}

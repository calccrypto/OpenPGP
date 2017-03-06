#include "PKAs.h"

bool PKA::can_encrypt(const uint8_t alg){
    return ((alg == PKA::ID::RSA_Encrypt_or_Sign) ||
            (alg == PKA::ID::RSA_Encrypt_Only)    ||
            (alg == PKA::ID::ElGamal));
}

bool PKA::can_sign(const uint8_t alg){
    return ((alg == PKA::ID::RSA_Encrypt_or_Sign) ||
            (alg == PKA::ID::RSA_Sign_Only)       ||
            (alg == PKA::ID::DSA));
}

bool is_RSA(const uint8_t alg){
    return ((alg == PKA::ID::RSA_Encrypt_or_Sign) ||
            (alg == PKA::ID::RSA_Encrypt_Only)    ||
            (alg == PKA::ID::RSA_Sign_Only));
}

void generate_key_pair(const uint8_t pka, const PKA::Params & params, PKA::Values & pub, PKA::Values & pri){
    switch (pka){
        case PKA::ID::RSA_Encrypt_or_Sign:
        case PKA::ID::RSA_Encrypt_Only:
        case PKA::ID::RSA_Sign_Only:
            {
                PKA::Values temp = RSA_keygen(params[0]);
                pub = {temp[0], temp[1]};
                pri = {temp[2]};
            }
            break;
        case PKA::ID::ElGamal:
            {
                PKA::Values temp = ElGamal_keygen(params[0]);
                pub = {temp[0], temp[1]};
                pri = {temp[2]};
            }
            break;
        case PKA::ID::DSA:
            pub = new_DSA_public(params[0], params[1]);
            pri = DSA_keygen(pub);
            break;
        default:
            throw std::runtime_error("Error: Undefined or reserved PKA number: " + std::to_string(pka));
            break;
    }
}

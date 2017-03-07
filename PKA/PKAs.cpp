#include "PKAs.h"

bool PKA::can_encrypt(const uint8_t alg){
    return ((alg == PKA::RSA_ENCRYPT_OR_SIGN) ||
            (alg == PKA::RSA_ENCRYPT_ONLY)    ||
            (alg == PKA::ELGAMAL));
}

bool PKA::can_sign(const uint8_t alg){
    return ((alg == PKA::RSA_ENCRYPT_OR_SIGN) ||
            (alg == PKA::RSA_SIGN_ONLY)       ||
            (alg == PKA::DSA));
}

bool is_RSA(const uint8_t alg){
    return ((alg == PKA::RSA_ENCRYPT_OR_SIGN) ||
            (alg == PKA::RSA_ENCRYPT_ONLY)    ||
            (alg == PKA::RSA_SIGN_ONLY));
}

void generate_key_pair(const uint8_t pka, const PKA::Params & params, PKA::Values & pub, PKA::Values & pri){
    switch (pka){
        case PKA::RSA_ENCRYPT_OR_SIGN:
        case PKA::RSA_ENCRYPT_ONLY:
        case PKA::RSA_SIGN_ONLY:
            {
                PKA::Values temp = RSA_keygen(params[0]);
                pub = {temp[0], temp[1]};
                pri = {temp[2]};
            }
            break;
        case PKA::ELGAMAL:
            {
                PKA::Values temp = ElGamal_keygen(params[0]);
                pub = {temp[0], temp[1]};
                pri = {temp[2]};
            }
            break;
        case PKA::DSA:
            pub = new_DSA_public(params[0], params[1]);
            pri = DSA_keygen(pub);
            break;
        default:
            throw std::runtime_error("Error: Undefined or reserved PKA number: " + std::to_string(pka));
            break;
    }
}

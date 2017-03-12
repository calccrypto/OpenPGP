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

PKA::Params generate_pka_params(const uint8_t pka, const std::size_t bits){
    PKA::Params params = {bits};

    switch (pka){
        case PKA::RSA_ENCRYPT_OR_SIGN:
        case PKA::RSA_ENCRYPT_ONLY:
        case PKA::RSA_SIGN_ONLY:
            break;
        case PKA::ELGAMAL:
            break;
        case PKA::DSA:
            if (bits & 1023){
                throw std::runtime_error("Error: DSA keysize should be 1024, 2048, or 3072 bits.");
            }

            params.push_back((bits == 1024)?160:256);
            break;
        default:
            throw std::runtime_error("Error: Undefined or reserved PKA number: " + std::to_string(pka));
            break;
    }

    return params;
}

uint8_t generate_keypair(const uint8_t pka, const PKA::Params & params, PKA::Values & pri, PKA::Values & pub){
    switch (pka){
        case PKA::RSA_ENCRYPT_OR_SIGN:
        case PKA::RSA_ENCRYPT_ONLY:
        case PKA::RSA_SIGN_ONLY:
            pub = RSA_keygen(params[0]);                // n, e
            pri = {pub[2], pub[3], pub[4], pub[5]};     // d, p, q, u
            pub.pop_back();                             // u
            pub.pop_back();                             // q
            pub.pop_back();                             // p
            pub.pop_back();                             // d
            break;
        case PKA::ELGAMAL:
            pub = ElGamal_keygen(params[0]);            // p, g, y
            pri = {pub[2]};                             // x
            pub.pop_back();                             // x
            break;
        case PKA::DSA:
            pub = new_DSA_public(params[0], params[1]); // p, q, g
            pri = DSA_keygen(pub);                      // x
            break;
        default:
            throw std::runtime_error("Error: Undefined or reserved PKA number: " + std::to_string(pka));
            break;
    }

    return pka;
}

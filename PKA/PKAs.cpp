#include "PKAs.h"

namespace OpenPGP {
namespace PKA {

bool can_encrypt(const uint8_t alg){
    return ((alg == ID::RSA_ENCRYPT_OR_SIGN) ||
            (alg == ID::RSA_ENCRYPT_ONLY)    ||
            (alg == ID::ELGAMAL)
            #ifdef GPG_COMPATIBLE
         || (alg == ID::ECDH)
            #endif
    );
}

bool can_sign(const uint8_t alg){
    return ((alg == ID::RSA_ENCRYPT_OR_SIGN) ||
            (alg == ID::RSA_SIGN_ONLY)       ||
            (alg == ID::DSA)
            #ifdef GPG_COMPATIBLE
         || (alg == ID::ECDSA)
         || (alg == ID::EdDSA)
            #endif
    );
}

bool is_RSA(const uint8_t alg){
    return ((alg == ID::RSA_ENCRYPT_OR_SIGN) ||
            (alg == ID::RSA_ENCRYPT_ONLY)    ||
            (alg == ID::RSA_SIGN_ONLY));
}

Params generate_params(const uint8_t pka, const std::size_t bits){
    Params params = {bits};

    switch (pka){
        case ID::RSA_ENCRYPT_OR_SIGN:
        case ID::RSA_ENCRYPT_ONLY:
        case ID::RSA_SIGN_ONLY:
            break;
        case ID::ELGAMAL:
            break;
        case ID::DSA:
            if (bits & 1023){
                // "Error: DSA keysize should be 1024, 2048, or 3072 bits.\n";
                return {};
            }

            params.push_back((bits == 1024)?160:256);
            break;
        default:
            // "Error: Undefined or reserved PKA number: " + std::to_string(pka) + "\n";
            return {};
            break;
    }

    return params;
}

uint8_t generate_keypair(const uint8_t pka, const Params & params, Values & pri, Values & pub){
    if (!params.size()){
        // "Error: No PKA key generation configuration provided.\n";
        return 0;
    }

    switch (pka){
        case ID::RSA_ENCRYPT_OR_SIGN:
        case ID::RSA_ENCRYPT_ONLY:
        case ID::RSA_SIGN_ONLY:
            pub = RSA::keygen(params[0]);                // n, e, d, p, q, u
            if (!pub.size()){
                // "Error: Bad RSA key generation values.\n";
                return 0;
            }
            pri = {pub[2], pub[3], pub[4], pub[5]};      // d, p, q, u
            pub.pop_back();                              // u
            pub.pop_back();                              // q
            pub.pop_back();                              // p
            pub.pop_back();                              // d
            break;
        case ID::ELGAMAL:
            pub = ElGamal::keygen(params[0]);            // p, g, y, x
            pri = {pub[3]};                              // x
            pub.pop_back();                              // x
            break;
        case ID::DSA:
            pub = DSA::new_public(params[0], params[1]); // p, q, g
            pri = DSA::keygen(pub);                      // x
            break;
        default:
            // "Error: Undefined or reserved PKA number: " + std::to_string(pka) + "\n";
            return 0;
            break;
    }

    return pka;
}

}
}
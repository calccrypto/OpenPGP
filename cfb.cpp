#include "cfb.h"

SymAlg::Ptr use_sym_alg(const uint8_t sym_alg, const std::string & key, const std::string & key2, const std::string & key3){
    SymAlg::Ptr alg;
    switch(sym_alg){
        case 1:
            alg = std::make_shared<IDEA>(key);
            break;
        case 2:
            alg = std::make_shared<TDES>(key, TDES_mode1, key2, TDES_mode2, key3, TDES_mode3);
            break;
        case 3:
            alg = std::make_shared<CAST128>(key);
            break;
        case 4:
            alg = std::make_shared<Blowfish>(key);
            break;
        case 7: case 8: case 9:
            alg = std::make_shared<AES>(key);
            break;
        case 10:
            alg = std::make_shared<Twofish>(key);
            break;
        case 11: case 12: case 13:
            alg = std::make_shared<Camellia>(key);
            break;
        default:
            throw std::runtime_error("Error: Unknown symmetric key algorithm value.");
            break;
    }
    return alg;
}

std::string OpenPGP_CFB_encrypt(SymAlg::Ptr & crypt, const uint8_t packet, const std::string & data, std::string prefix){
    const unsigned int BS = crypt -> blocksize() >> 3;

    if (prefix.size() > BS){
        prefix = prefix.substr(0, BS);
    }

    // 1
    std::string FR(BS, 0);
    // 2
    std::string FRE = crypt -> encrypt(FR);
    // 3
    FRE = xor_strings(FRE, prefix);
    std::string C = FRE;
    // 4
    FR = C;
    // 5
    FRE = crypt -> encrypt(FR);
    // 6
    C += xor_strings(FRE.substr(0, 2), prefix.substr(BS - 2, 2));
    // 7
    if (packet == 9){ // resynchronization
        FR = C.substr(2, BS);
        // 8
        FRE = crypt -> encrypt(FR);
        // 9
        C += xor_strings(FRE, data.substr(0, BS));
        unsigned int x = BS;
        while (x < data.size()){
            // 10
            FR = C.substr(x + 2, BS);
            // 11
            FRE = crypt -> encrypt(FR);
            // 12
            C += xor_strings(FRE, data.substr(x, BS));
            x += BS;
        }
    }
    else{ // no resynchronization
        // 8
        FRE = crypt -> encrypt(FR);
        // 9
        C += xor_strings(FRE.substr(2, BS - 2), data.substr(0, BS));
        C = C.substr(0, BS << 1);
        unsigned int x = BS;
        while (x < data.size()){
            // 10
            FR = C.substr(x, BS);
            // 11
            FRE = crypt -> encrypt(FR);
            // 12
            C += xor_strings(FRE, data.substr(x - 2, BS));
            x += BS;
        }
    }
    return C;
}

std::string OpenPGP_CFB_decrypt(SymAlg::Ptr & crypt, const uint8_t packet, const std::string & data){
    const unsigned int BS = crypt -> blocksize() >> 3;

    // 1
    std::string FR(BS, 0);

    // 2
    std::string FRE = crypt -> encrypt(FR);

    // 4
    FR = data.substr(0, BS);

    // 3
    std::string prefix = xor_strings(FRE, FR);

    // 5
    FRE = crypt -> encrypt(FR); // encryption of ciphertext
    std::string check = xor_strings(FRE.substr(0, 2), data.substr(BS, 2));

    // 6
    if (prefix.substr(BS - 2, 2) != check){
        throw std::runtime_error("Error: Bad OpenPGP_CFB check value.");
    }
    std::string P = "";
    unsigned int x = (packet == 9)?2:0; // 7
    while ((x + BS) < data.size()){
        P += xor_strings(FRE, data.substr(x, BS));
        FRE = crypt -> encrypt(data.substr(x, BS));
        x += BS;
    }
    P += xor_strings(FRE, data.substr(x, BS));
    return prefix + prefix.substr(BS - 2, 2) + P.substr(BS + 2, P.size() - BS - 2);
}

std::string use_OpenPGP_CFB_encrypt(const uint8_t sym_alg, const uint8_t packet, const std::string & data, const std::string & key, const std::string & prefix, const std::string & key2, const std::string & key3){
    if (!sym_alg){
        return data;
    }
    SymAlg::Ptr alg = use_sym_alg(sym_alg, key, key2, key3);
    std::string out = OpenPGP_CFB_encrypt(alg, packet, data, prefix);
    return out;
}

std::string use_OpenPGP_CFB_decrypt(const uint8_t sym_alg, const uint8_t packet, const std::string & data, const std::string & key, const std::string & key2, const std::string & key3){
    if (!sym_alg){
        return data;
    }
    SymAlg::Ptr alg = use_sym_alg(sym_alg, key, key2, key3);
    std::string out = OpenPGP_CFB_decrypt(alg, packet, data);
    return out;
}

std::string normal_CFB_encrypt(SymAlg::Ptr & crypt, std::string & data, std::string & IV){
    std::string out = "";
    const unsigned int BS = crypt -> blocksize() >> 3;
    unsigned int x = 0;
    while (out.size() < data.size()){
        IV = xor_strings(crypt -> encrypt(IV), data.substr(x, BS));
        out += IV;
        x += BS;
    }
    return out;
}

std::string normal_CFB_decrypt(SymAlg::Ptr & crypt, std::string & data, std::string & IV){
    std::string out = "";
    const unsigned int BS = crypt -> blocksize() >> 3;
    unsigned int x = 0;
    while (x < data.size()){
        out += xor_strings(crypt -> encrypt(IV), data.substr(x, BS));
        IV = data.substr(x, BS);
        x += BS;
    }
    return out;
}

std::string use_normal_CFB_encrypt(const uint8_t sym_alg, std::string data, std::string key, std::string IV, std::string key2, std::string key3){
    if (!sym_alg){
        return data;
    }
    SymAlg::Ptr alg = use_sym_alg(sym_alg, key, key2, key3);
    std::string out = normal_CFB_encrypt(alg, data, IV);
    return out;
}

std::string use_normal_CFB_decrypt(const uint8_t sym_alg, std::string data, std::string key, std::string IV, std::string key2, std::string key3){
    if (!sym_alg){
        return data;
    }
    SymAlg::Ptr alg = use_sym_alg(sym_alg, key, key2, key3);
    std::string out = normal_CFB_decrypt(alg, data, IV);
    return out;
}

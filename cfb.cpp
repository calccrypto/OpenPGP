#include "cfb.h"

std::string xor_strings(std::string str1, std::string str2){
    std::string out = "";
    for(unsigned int x = 0; x < std::min(str1.size(), str2.size()); x++){
        out += std::string(1, str1[x] ^ str2[x]);
    }
    return out;
}

std::string OpenPGP_CFB_encrypt(SymAlg * crypt, uint8_t packet, std::string data, std::string prefix){
    unsigned int BS = crypt -> blocksize() >> 3;

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

std::string OpenPGP_CFB_decrypt(SymAlg * crypt, uint8_t packet, std::string data){
    unsigned int BS = crypt -> blocksize() >> 3;
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
        std::cerr << "Error: Bad OpenPGP_CFB check value." << std::endl;
        exit(1);
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

std::string use_OpenPGP_CFB_encrypt(uint8_t sym_alg, uint8_t packet, std::string data, std::string key, std::string prefix, std::string key2, std::string key3){
    SymAlg * alg = NULL;
    switch(sym_alg){
        case 0: // unencrypted
            return data;
            break;
        case 1:
            alg = new IDEA(key);
            break;
        case 2:
            alg = new TDES(key, TDES_mode1, key2, TDES_mode2, key3, TDES_mode3);
            break;
        case 3:
            alg = new CAST128(key);
            break;
        case 4:
            alg = new Blowfish(key);
            break;
        case 7: case 8: case 9:
            alg = new AES(key);
            break;
        case 10:
            std::cerr << "Error: Twofish has not yet been implemented yet." << std::endl;
            exit(1);
            break;
        default:
            std::cerr << "Error: Unknown symmetric key algorithm value." << std::endl;
            exit(1);
    }
    return OpenPGP_CFB_encrypt(alg, packet, data, prefix);
}

std::string use_OpenPGP_CFB_decrypt(uint8_t sym_alg, uint8_t packet, std::string data, std::string key, std::string key2, std::string key3){
    SymAlg * alg = NULL;
    switch(sym_alg){
        case 0: // unencrypted
            return data;
            break;
        case 1:
            alg = new IDEA(key);
            break;
        case 2:
            alg = new TDES(key, TDES_mode1, key2, TDES_mode2, key3, TDES_mode3);
            break;
        case 3:
            alg = new CAST128(key);
            break;
        case 4:
            alg = new Blowfish(key);
            break;
        case 7: case 8: case 9:
            alg = new AES(key);
            break;
        case 10:
            std::cerr << "Error: Twofish has not yet been implemented yet." << std::endl;
            exit(1);
            break;
        default:
            std::cerr << "Error: Unknown symmetric key algorithm value." << std::endl;
            exit(1);
    }
    return OpenPGP_CFB_decrypt(alg, packet, data);
}

std::string normal_CFB_encrypt(SymAlg * crypt, std::string data, std::string IV){
    std::string out = "";
    unsigned int BS = crypt -> blocksize() >> 3;
    unsigned int x = 0;
    while (out.size() < data.size()){
        IV = xor_strings(crypt -> encrypt(IV), data.substr(x, BS));
        out += IV;
        x += BS;
    }
    return out;
}

std::string normal_CFB_decrypt(SymAlg * crypt, std::string data, std::string IV){
    std::string out = "";
    unsigned int BS = crypt -> blocksize() >> 3;
    unsigned int x = 0;
    while (out.size() < data.size()){
        out += xor_strings(crypt -> encrypt(IV), data.substr(x, BS));
        IV = data.substr(x, BS);
        x += BS;
    }
    return out;
}

std::string use_normal_CFB_encrypt(uint8_t sym_alg, std::string data, std::string key, std::string IV, std::string key2, std::string key3){
    SymAlg * alg = NULL;
    switch(sym_alg){
        case 0: // unencrypted
            return data;
            break;
        case 1:
            alg = new IDEA(key);
            break;
        case 2:
            alg = new TDES(key, TDES_mode1, key2, TDES_mode2, key3, TDES_mode3);
            break;
        case 3:
            alg = new CAST128(key);
            break;
        case 4:
            alg = new Blowfish(key);
            break;
        case 7: case 8: case 9:
            alg = new AES(key);
            break;
        case 10:
            std::cerr << "Error: Twofish has not yet been implemented yet." << std::endl;
            exit(1);
            break;
        default:
            std::cerr << "Error: Unknown symmetric key algorithm value." << std::endl;
            exit(1);
    }
    return normal_CFB_encrypt(alg, data, IV);
}

std::string use_normal_CFB_decrypt(uint8_t sym_alg, std::string data, std::string key, std::string IV, std::string key2, std::string key3){
    SymAlg * alg = NULL;
    switch(sym_alg){
        case 0: // unencrypted
            return data;
            break;
        case 1:
            alg = new IDEA(key);
            break;
        case 2:
            alg = new TDES(key, TDES_mode1, key2, TDES_mode2, key3, TDES_mode3);
            break;
        case 3:
            alg = new CAST128(key);
            break;
        case 4:
            alg = new Blowfish(key);
            break;
        case 7: case 8: case 9:
            alg = new AES(key);
            break;
        case 10:
            std::cerr << "Error: Twofish has not yet been implemented yet." << std::endl;
            exit(1);
            break;
        default:
            std::cerr << "Error: Unknown symmetric key algorithm value." << std::endl;
            exit(1);
    }
    return normal_CFB_decrypt(alg, data, IV);
}

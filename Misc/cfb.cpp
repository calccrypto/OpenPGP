#include "cfb.h"

namespace OpenPGP {

std::string OpenPGP_CFB_encrypt(const SymAlg::Ptr & crypt, const uint8_t packet, const std::string & data, std::string prefix){
    const std::size_t BS = crypt -> blocksize() >> 3;

    if (prefix.size() < (BS + 2)){
        throw std::runtime_error("Error: Given prefix too short.");
    }
    else if (prefix.size() > (BS + 2)){
        prefix = prefix.substr(0, BS + 2);    // reduce prefix
    }

    // 13.9. OpenPGP CFB Mode
    //
    //    OpenPGP does symmetric encryption using a variant of Cipher Feedback
    //    mode (CFB mode). This section describes the procedure it uses in
    //    detail. This mode is what is used for Symmetrically Encrypted Data
    //    Packets; the mechanism used for encrypting secret-key material is
    //    similar, and is described in the sections above.
    //
    //    In the description below, the value BS is the block size in octets of
    //    the cipher. Most ciphers have a block size of 8 octets. The AES and
    //    Twofish have a block size of 16 octets. Also note that the
    //    description below assumes that the IV and CFB arrays start with an
    //    index of 1 (unlike the C language, which assumes arrays start with a
    //    zero index).
    //
    //    OpenPGP CFB mode uses an initialization vector (IV) of all zeros, and
    //    prefixes the plaintext with BS+2 octets of random data, such that
    //    octets BS+1 and BS+2 match octets BS-1 and BS. It does a CFB
    //    resynchronization after encrypting those BS+2 octets.
    //
    //    Thus, for an algorithm that has a block size of 8 octets (64 bits),
    //    the IV is 10 octets long and ocets 7 and 8 of the IV are the same as
    //    octets 9 and 10. For an algorithm with a block size of 16 octets
    //    (128 bits), the IV is 18 octets long, and octets 17 and 18 replicate
    //    octets 15 and 16. Those extra two octets are an easy check for a
    //    correct key.
    //
    //    Step by step, here is the procedure:

    //    1. The feedback register (FR) is set to the IV, which is all zeros.
    std::string FR(BS, 0);

    //    2. FR is encrypted to produce FRE (FR Encrypted). This is the encryption of an all-zero value.
    std::string FRE = crypt -> encrypt(FR);

    //    3. FRE is xored with the first BS octets of random data prefixed to the plaintext to produce C[1] through C[BS], the first BS octets of ciphertext.
    FRE = xor_strings(FRE, prefix);
    std::string C = FRE;

    //    4. FR is loaded with C[1] through C[BS].
    FR = C;

    //    5. FR is encrypted to produce FRE, the encryption of the first BS octets of ciphertext.
    FRE = crypt -> encrypt(FR);

    if (packet == Packet::SYMMETRICALLY_ENCRYPTED_DATA){                    // resynchronization
        //    6. The left two octets of FRE get xored with the next two octets of data that were prefixed to the plaintext. This produces C[BS+1] and C[BS+2], the next two octets of ciphertext.
        C += xor_strings(FRE.substr(0, 2), prefix.substr(BS - 2, 2));

        //    7. (The resynchronization step) FR is loaded with C[3] through C[BS+2].
        FR = C.substr(2, BS);

        //    8. FR is encrypted to produce FRE.
        FRE = crypt -> encrypt(FR);

        //    9. FRE is xored with the first BS octets of the given plaintext, now that we have finished encrypting the BS+2 octets of prefixed data. This produces C[BS+3] through C[BS+(BS+2)], the next BS octets of ciphertext.
        C += xor_strings(FRE, data.substr(0, BS));
    }
    else if (packet == Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA){     // no resynchronization
        // 5.13. Sym. Encrypted Integrity Protected Data Packet (Tag 18)
        //
        //    Unlike the Symmetrically Encrypted Data Packet, no
        //    special CFB resynchronization is done after encrypting this prefix
        //    data.

        // Second block of ciphertext is the 2 repeated octets + the first BS - 2 octets of the plaintext
        C += xor_strings(FRE, prefix.substr(BS - 2, 2) + data.substr(0, BS - 2));
    }
    else{
        throw std::runtime_error("Error: Bad Packet Type");
    }

    std::string::size_type x = BS - ((packet == Packet::SYMMETRICALLY_ENCRYPTED_DATA)?0:2);
    while (x < data.size()){
        //    10. FR is loaded with C[BS+3] to C[BS + (BS+2)] (which is C11-C18 for an 8-octet block).
        FR = C.substr(x + 2, BS);

        //    11. FR is encrypted to produce FRE.
        FRE = crypt -> encrypt(FR);

        //    12. FRE is xored with the next BS octets of plaintext, to produce the next BS octets of ciphertext. These are loaded into FR, and the process is repeated until the plaintext is used up.
        C += xor_strings(FRE, data.substr(x, BS));

        x += BS;
    }

    return C;
}

std::string OpenPGP_CFB_decrypt(const SymAlg::Ptr & crypt, const uint8_t packet, const std::string & data){
    const std::size_t BS = crypt -> blocksize() >> 3;

    //    1. The feedback register (FR) is set to the IV, which is all zeros.
    std::string FR(BS, 0);

    //    2. FR is encrypted to produce FRE (FR Encrypted). This is the encryption of an all-zero value.
    std::string FRE = crypt -> encrypt(FR);

    //    4. FR is loaded with C[1] through C[BS].
    FR = data.substr(0, BS);

    //    3. FRE is xored with the first BS octets of random data prefixed to the plaintext to produce C[1] through C[BS], the first BS octets of ciphertext.
    std::string prefix = xor_strings(FRE, FR);

    //    5. FR is encrypted to produce FRE, the encryption of the first BS octets of ciphertext.
    FRE = crypt -> encrypt(FR); // encryption of ciphertext

    //    6. The left two octets of FRE get xored with the next two octets of data that were prefixed to the plaintext. This produces C[BS+1] and C[BS+2], the next two octets of ciphertext.
    if (prefix.substr(BS - 2, 2) != xor_strings(FRE.substr(0, 2), data.substr(BS, 2))){
        throw std::runtime_error("Error: Bad OpenPGP_CFB check value.");
    }

    std::string P = "";
    std::string::size_type x = (packet == Packet::SYMMETRICALLY_ENCRYPTED_DATA)?2:0;
    while ((x + BS) < data.size()){
        std::string substr = data.substr(x, BS);
        P += xor_strings(FRE, substr);
        FRE = crypt -> encrypt(substr);
        x += BS;
    }
    P += xor_strings(FRE, data.substr(x, BS));
    P = P.substr(BS, P.size() - BS);

    return prefix + ((packet == 9)?prefix.substr(BS - 2, 2):std::string("")) + P;   // only add prefix 2 octets when resyncing - already shows up without resync
}

std::string use_OpenPGP_CFB_encrypt(const uint8_t sym_alg, const uint8_t packet, const std::string & data, const std::string & key, const std::string & prefix){
    if (!sym_alg){
        return data;
    }

    const SymAlg::Ptr alg = Sym::setup(sym_alg, key);
    return OpenPGP_CFB_encrypt(alg, packet, data, prefix);
}

std::string use_OpenPGP_CFB_decrypt(const uint8_t sym_alg, const uint8_t packet, const std::string & data, const std::string & key){
    if (!sym_alg){
        return data;
    }

    const SymAlg::Ptr alg = Sym::setup(sym_alg, key);
    return OpenPGP_CFB_decrypt(alg, packet, data);
}

std::string normal_CFB_encrypt(const SymAlg::Ptr & crypt, const std::string & data, std::string IV){
    std::string out = "";
    const std::size_t BS = crypt -> blocksize() >> 3;
    std::string::size_type x = 0;
    while (out.size() < data.size()){
        IV = xor_strings(crypt -> encrypt(IV), data.substr(x, BS));
        out += IV;
        x += BS;
    }
    return out;
}

std::string normal_CFB_decrypt(const SymAlg::Ptr & crypt, const std::string & data, std::string IV){
    std::string out = "";
    const std::size_t BS = crypt -> blocksize() >> 3;
    std::string::size_type x = 0;
    while (x < data.size()){
        out += xor_strings(crypt -> encrypt(IV), data.substr(x, BS));
        IV = data.substr(x, BS);
        x += BS;
    }
    return out;
}

std::string use_normal_CFB_encrypt(const uint8_t sym_alg, const std::string & data, const std::string & key, const std::string & IV){
    if (!sym_alg){
        return data;
    }

    const SymAlg::Ptr alg = Sym::setup(sym_alg, key);
    return normal_CFB_encrypt(alg, data, IV);
}

std::string use_normal_CFB_decrypt(const uint8_t sym_alg, const std::string & data, const std::string & key, const std::string & IV){
    if (!sym_alg){
        return data;
    }

    const SymAlg::Ptr alg = Sym::setup(sym_alg, key);
    return normal_CFB_decrypt(alg, data, IV);
}

}
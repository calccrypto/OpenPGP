#include "encrypt.h"
Tag6 * find_encrypting_key(PGP & k){
    if ((k.get_ASCII_Armor() == 1) || (k.get_ASCII_Armor() == 2)){
        std::vector <Packet *> packets = k.get_packets();
        for(Packet *& p : packets){
            if ((p -> get_tag() == 5) || (p -> get_tag() == 6) || (p -> get_tag() == 7) || (p -> get_tag() == 14)){
                std::string data = p -> raw();
                Tag6 * key = new Tag6(data);
                // make sure key has signing material
                if ((key -> get_pka() == 1) || // RSA
                    (key -> get_pka() == 2) || // RSA
                    (key -> get_pka() == 16)){ // ElGamal
                        return key;
                }
                delete key;
            }
        }
    }
    return NULL;
}

std::vector <mpz_class> pka_encrypt(const uint8_t pka, mpz_class data, const std::vector <mpz_class> & pub){
    if (pka < 3){   // RSA
        return {RSA_encrypt(data, pub)};
    }
    if (pka == 16){ // ElGamal
        return ElGamal_encrypt(data, pub);
    }
    else{
        std::stringstream s; s << (int) pka;
        throw std::runtime_error("Error: PKA number " + s.str() + " not allowed or unknown.");
    }
    return {}; // should never reach here; mainly just to remove compiler warnings
}

std::vector <mpz_class> pka_encrypt(const uint8_t pka, const std::string & data, const std::vector <mpz_class> & pub){
    return pka_encrypt(pka, mpz_class(hexlify(data), 16), pub);
}

PGP encrypt(const std::string & data, PGP & pub, bool hash, uint8_t sym_alg){
    BBS((mpz_class) (int) now()); // seed just in case not seeded

    if ((pub.get_ASCII_Armor() != 1) && (pub.get_ASCII_Armor() != 2)){
        throw std::runtime_error("Error: No encrypting key found.");
    }

    std::vector <Packet *> packets = pub.get_packets();
    Tag6 * public_key = find_encrypting_key(pub);

    if (!public_key){
        throw std::runtime_error("Error: No encrypting key found.");
    }

    // Check if key has been revoked
    if (check_revoked(packets, public_key -> get_keyid())){
        throw std::runtime_error("Error: Key " + hexlify(public_key -> get_keyid()) + " has been revoked. Nothing done.");
    }

    std::vector <mpz_class> mpi = public_key -> get_mpi();
    Tag1 * tag1 = new Tag1;
    tag1 -> set_keyid(public_key -> get_keyid());
    tag1 -> set_pka(public_key -> get_pka());

    // do calculations

    // generate session key
    uint16_t key_len = Symmetric_Algorithm_Key_Length.at(Symmetric_Algorithms.at(sym_alg));
    std::string session_key = mpz_class(BBS().rand(key_len), 2).get_str(16);
    session_key = unhexlify(std::string((key_len >> 2) - session_key.size(), '0') + session_key);

    // get checksum of session key
    uint16_t sum = 0;
    for(char & x : session_key){
        sum += (unsigned char) x;
    }

    std::string nibbles = mpi[0].get_str(16);      // get hex representation of modulus
    nibbles += std::string(nibbles.size() & 1, 0); // get even number of nibbles
    mpz_class m(hexlify(EME_PKCS1v1_5_ENCODE(std::string(1, sym_alg) + session_key + unhexlify(makehex(sum, 4)), nibbles.size() >> 1)), 16);

    // encrypt m
    tag1 -> set_mpi(pka_encrypt(public_key -> get_pka(), m, mpi));

    // Literal Data Packet
    Tag11 tag11;
    tag11.set_format('t');
    tag11.set_filename("");
    tag11.set_time(0);
    tag11.set_literal(data);

    // generate prefix
    uint16_t BS = Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(sym_alg)) >> 3;
    std::string prefix = unhexlify(zfill(bintohex(BBS().rand(BS << 3)), BS << 1));

    Packet * encrypted = NULL;

    if (!hash){
        // Symmetrically Encrypted Data Packet
        Tag9 tag9;
        tag9.set_encrypted_data(use_OpenPGP_CFB_encrypt(sym_alg, 9, tag11.write(true), session_key, prefix));
        std::string raw = tag9.raw();
        encrypted = new Tag9;
        encrypted -> read(raw);
    }
    else{
        // Sym. Encrypted Integrity Protected Data Packet
        Tag18 tag18;
        tag18.set_protected_data(tag11.write(true));

        // Modification Detection Code Packet
        Tag19 tag19;
        tag19.set_hash(use_hash(2, prefix + prefix.substr(BS - 2, 2) + tag18.get_protected_data() + "\xd3\x14"));

        // encrypt((literal_data_packet(plain text) + MDC SHA1(20 octets)))
        tag18.set_protected_data(use_OpenPGP_CFB_encrypt(sym_alg, 18, tag18.get_protected_data() + tag19.write(), session_key, prefix));
        std::string raw = tag18.raw();
        encrypted = new Tag18;
        encrypted -> read(raw);
    }

    // write data to output container
    PGP out;
    out.set_ASCII_Armor(0);
    std::vector <std::pair <std::string, std::string> > header;
    header.push_back(std::pair <std::string, std::string> ("Version", "cc"));
    out.set_Armor_Header(header);
    packets = {tag1, encrypted};
    out.set_packets(packets);

    // erase data
    m = 0;
    session_key = "";
    prefix = "";
    delete tag1;
    delete public_key;
    delete encrypted;
    return out;
}

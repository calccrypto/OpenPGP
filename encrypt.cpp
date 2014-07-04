#include "encrypt.h"
Tag6::Ptr find_encrypting_key(const PGP & k){
    if ((k.get_ASCII_Armor() == 1) || (k.get_ASCII_Armor() == 2)){
        std::vector <Packet::Ptr> packets = k.get_packets();
        for(Packet::Ptr const & p : packets){
            if ((p -> get_tag() == 5) || (p -> get_tag() == 6) || (p -> get_tag() == 7) || (p -> get_tag() == 14)){
                std::string data = p -> raw();
                Tag6::Ptr key(new Tag6(data));
                // make sure key has signing material
                if ((key -> get_pka() == 1) || // RSA
                    (key -> get_pka() == 2) || // RSA
                    (key -> get_pka() == 16)){ // ElGamal
                        return key;
                }
            }
        }
    }
    return Tag6::Ptr();
}

std::vector <PGPMPI> pka_encrypt(const uint8_t pka, PGPMPI data, const std::vector <PGPMPI> & pub){
    if (pka < 3){   // RSA
        return {RSA_encrypt(data, pub)};
    }
    if (pka == 16){ // ElGamal
        return ElGamal_encrypt(data, pub);
    }
    else{
        std::stringstream s; s << static_cast <int> (pka);
        throw std::runtime_error("Error: PKA number " + s.str() + " not allowed or unknown.");
    }
    return {}; // should never reach here; mainly just to remove compiler warnings
}

std::vector <PGPMPI> pka_encrypt(const uint8_t pka, const std::string & data, const std::vector <PGPMPI> & pub){
    return pka_encrypt(pka, rawtompi(data), pub);
}

PGP encrypt(const std::string & data, const PGP & pub, bool hash, uint8_t sym_alg){
    BBS(static_cast <PGPMPI> (static_cast <int> (now()))); // seed just in case not seeded

    if ((pub.get_ASCII_Armor() != 1) && (pub.get_ASCII_Armor() != 2)){
        throw std::runtime_error("Error: No encrypting key found.");
    }

    std::vector <Packet::Ptr> packets = pub.get_packets();
    Tag6::Ptr public_key = find_encrypting_key(pub);

    if (!public_key){
        throw std::runtime_error("Error: No encrypting key found.");
    }

    // Check if key has been revoked
    if (check_revoked(packets, public_key -> get_keyid())){
        throw std::runtime_error("Error: Key " + hexlify(public_key -> get_keyid()) + " has been revoked. Nothing done.");
    }

    std::vector <PGPMPI> mpi = public_key -> get_mpi();
    Tag1::Ptr tag1 = std::make_shared<Tag1>();
    tag1 -> set_keyid(public_key -> get_keyid());
    tag1 -> set_pka(public_key -> get_pka());

    // do calculations

    // generate session key
    uint16_t key_len = Symmetric_Algorithm_Key_Length.at(Symmetric_Algorithms.at(sym_alg));
    std::string session_key = mpitohex(bintompi(BBS().rand(key_len)));
    session_key = unhexlify(std::string((key_len >> 2) - session_key.size(), '0') + session_key);

    // get checksum of session key
    uint16_t sum = 0;
    for(char & x : session_key){
        sum += static_cast <unsigned char> (x);
    }

    std::string nibbles = mpitohex(mpi[0]);      // get hex representation of modulus
    nibbles += std::string(nibbles.size() & 1, 0); // get even number of nibbles
    PGPMPI m = hextompi(hexlify(EME_PKCS1v1_5_ENCODE(std::string(1, sym_alg) + session_key + unhexlify(makehex(sum, 4)), nibbles.size() >> 1)));

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

    Packet::Ptr encrypted;

    if (!hash){
        // Symmetrically Encrypted Data Packet
        Tag9 tag9;
        tag9.set_encrypted_data(use_OpenPGP_CFB_encrypt(sym_alg, 9, tag11.write(true), session_key, prefix));
        std::string raw = tag9.raw();
        encrypted = std::make_shared<Tag9>();
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
        encrypted = std::make_shared<Tag18>();
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
    return out;
}

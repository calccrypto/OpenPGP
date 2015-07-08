#include "encrypt.h"

Tag6::Ptr find_encrypting_key(const PGP & k){
    if ((k.get_ASCII_Armor() == 1) || (k.get_ASCII_Armor() == 2)){
        for(Packet::Ptr const & p : k.get_packets()){
            if ((p -> get_tag() == 5) || (p -> get_tag() == 6) || (p -> get_tag() == 7) || (p -> get_tag() == 14)){
                std::string data = p -> raw();
                Tag6::Ptr key(new Tag6(data));
                // make sure key has encrypting keys
                if ((key -> get_pka() == 1) || // RSA
                    (key -> get_pka() == 2) || // RSA
                    (key -> get_pka() == 16)){ // ElGamal
                        return key;
                }
                key.reset();
            }
        }
    }
    return nullptr;
}

std::vector <PGPMPI> pka_encrypt(const uint8_t pka, PGPMPI data, const std::vector <PGPMPI> & pub){
    if (pka < 3){   // RSA
        return {RSA_encrypt(data, pub)};
    }
    if (pka == 16){ // ElGamal
        return ElGamal_encrypt(data, pub);
    }
    else{
        std::stringstream s; s << static_cast <unsigned int> (pka);
        throw std::runtime_error("Error: PKA number " + s.str() + " not allowed or unknown.");
    }
    return {}; // should never reach here; mainly just to remove compiler warnings
}

std::vector <PGPMPI> pka_encrypt(const uint8_t pka, const std::string & data, const std::vector <PGPMPI> & pub){
    return pka_encrypt(pka, rawtompi(data), pub);
}

Packet::Ptr encrypt_data(const std::string & session_key, const std::string & data, const std::string & filename, const uint8_t sym_alg, const uint8_t comp, const bool mdc, const PGPSecretKey::Ptr & signer, const std::string & sig_passphrase){
    // generate prefix
    uint16_t BS = Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(sym_alg)) >> 3;
    std::string prefix = unhexlify(zfill(bintohex(BBS().rand(BS << 3)), BS << 1, '0'));

    std::string to_encrypt;

    // put data in Literal Data Packet
    Tag11 tag11;
    tag11.set_format('t');
    tag11.set_filename(filename);
    tag11.set_time(0);
    tag11.set_literal(data);

    to_encrypt = tag11.write(2);

    // // if message is to be signed
    // if (signer){
        // // find preferred hash and compression algorithms of the signer
        // // find signing key id
        // Tag5::Ptr tag5 = find_signing_key(*signer, 5);
        // std::string keyid = tag5 -> get_keyid();
        // tag5.reset();

        // // find signature packet of signing key
        // Tag2::Ptr tag2 = nullptr;
        // for(Packet::Ptr const & p : signer -> get_packets()){
            // if (p -> get_tag() == 2){
                // std::string raw = p -> raw();
                // Tag2 sig(raw);

                // if (sig.get_keyid() == keyid){
                    // tag2 = std::make_shared <Tag2> (sig);
                    // break;
                // }
            // }
        // }

        // uint8_t h = 2; // default SHA1
        // uint8_t c = comp;
        // // if a signature packet was found
        // if (tag2){
            // // check for preferred hash algorithms
            // std::string raw = tag2 -> find_subpacket(21);
            // if (raw.size()){
                // Tag2Sub21 tag2sub21(raw);
                // h = tag2sub21.get_pha()[0]; // use first preferred hash algorithm
            // }
            // // check for preferred compression algorithms
            // raw = tag2 -> find_subpacket(22);
            // if (raw.size()){
                // Tag2Sub22 tag2sub22(raw);
                // h = tag2sub22.get_pca()[0]; // use first preferred compression algorithm
            // }
        // }
        // to_encrypt = sign_message(*signer, sig_passphrase, filename, tag11.write(2), h, c).write(2);
    // }

    if (comp){
        // Compressed Data Packet (Tag 8)
        Tag8 tag8;
        tag8.set_comp(comp);
        tag8.set_data(to_encrypt); // put source data into compressed packet
        to_encrypt = tag8.write(2);
    }

    Packet::Ptr encrypted = nullptr;

    if (!mdc){
        // Symmetrically Encrypted Data Packet (Tag 9)
        Tag9 tag9;
        tag9.set_encrypted_data(use_OpenPGP_CFB_encrypt(sym_alg, 9, to_encrypt, session_key, prefix));
        encrypted = std::make_shared<Tag9>(tag9);
    }
    else{
        // Modification Detection Code Packet (Tag 19)
        Tag19 tag19;
        tag19.set_hash(use_hash(2, prefix + prefix.substr(BS - 2, 2) + to_encrypt + "\xd3\x14"));

        // Sym. Encrypted Integrity Protected Data Packet (Tag 18)
        Tag18 tag18;
        // encrypt(compressed(literal_data_packet(plain text)) + MDC SHA1(20 octets))
        tag18.set_protected_data(use_OpenPGP_CFB_encrypt(sym_alg, 18, to_encrypt + tag19.write(), session_key, prefix));
        encrypted = std::make_shared<Tag18>(tag18);
    }

    return encrypted;
}

PGPMessage encrypt_pka(const PGPPublicKey & pub, const std::string & data, const std::string & filename, const uint8_t sym_alg, const uint8_t comp, const bool mdc, const PGPSecretKey::Ptr & signer, const std::string & sig_passphrase){
    BBS(static_cast <PGPMPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded

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
    // get hex version of session key
    std::string session_key = mpitohex(bintompi(BBS().rand(key_len)));
    // unhexlify session key
    session_key = unhexlify(std::string((key_len >> 2) - session_key.size(), '0') + session_key);

    // get checksum of session key
    uint16_t sum = 0;
    for(char & x : session_key){
        sum += static_cast <unsigned char> (x);
    }

    std::string nibbles = mpitohex(mpi[0]);        // get hex representation of modulus
    nibbles += std::string(nibbles.size() & 1, 0); // get even number of nibbles
    PGPMPI m = hextompi(hexlify(EME_PKCS1v1_5_ENCODE(std::string(1, sym_alg) + session_key + unhexlify(makehex(sum, 4)), nibbles.size() >> 1)));

    // encrypt m
    tag1 -> set_mpi(pka_encrypt(public_key -> get_pka(), m, mpi));

    // encrypt data and put it into a packet
    Packet::Ptr encrypted = encrypt_data(session_key, data, filename, sym_alg, comp, mdc, signer, sig_passphrase);

    // write data to output container
    PGPMessage out = PGPMessage();
    out.set_ASCII_Armor(0);
    out.set_Armor_Header(std::vector <std::pair <std::string, std::string> > ({std::pair <std::string, std::string> ("Version", "cc")}));
    out.set_packets({tag1, encrypted});

    // clear data
    packets.clear();
    public_key.reset();
    tag1.reset();
    m = 0;
    session_key = "";
    encrypted.reset();

    return out;
}

PGPMessage encrypt_sym(const std::string & passphrase, const std::string & data, const std::string & filename, const uint8_t sym_alg, const uint8_t comp, const bool mdc, const PGPSecretKey::Ptr & signer, const std::string & sig_passphrase){
    std::cerr << "Warning: encrypt_sym is untested. Potentially incorrect" << std::endl;

    // generate Symmetric-Key Encrypted Session Key Packets (Tag 3)
    uint16_t key_len = Symmetric_Algorithm_Key_Length.at(Symmetric_Algorithms.at(sym_alg));

    S2K3::Ptr s2k = std::make_shared <S2K3> ();
    s2k -> set_type(3);
    s2k -> set_hash(2); // SHA1
    s2k -> set_salt(unhexlify(mpitohex(bintompi(BBS().rand(key_len)))));
    s2k -> set_count(96);

    Tag3::Ptr tag3 = std::make_shared <Tag3> ();
    tag3 -> set_version(4);
    tag3 -> set_sym(sym_alg);
    tag3 -> set_s2k(s2k);
    // don't set esk (?)

    // generate session key
    // get hex version of session key
    std::string session_key = mpitohex(bintompi(BBS().rand(key_len)));
    // unhexlify session key
    session_key = unhexlify(std::string((key_len >> 2) - session_key.size(), '0') + session_key);

    // encrypt session key
    std::string encrypted_session_key;

    // encrypt data
    Packet::Ptr encrypted = encrypt_data(encrypted_session_key, data, filename, sym_alg, comp, mdc, signer, sig_passphrase);

    // write to output container
    PGPMessage out;
    out.set_ASCII_Armor(0);
    out.set_Armor_Header(std::vector <std::pair <std::string, std::string> > ({std::pair <std::string, std::string> ("Version", "cc")}));
    out.set_packets({tag3, encrypted});

    // clear data
    s2k.reset();
    tag3.reset();
    session_key = "";
    encrypted_session_key = "";
    encrypted.reset();

    return out;
}

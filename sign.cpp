#include "sign.h"
Tag5 * find_signing_key(PGP & k){
    if (k.get_ASCII_Armor() == 2){
        std::vector <Packet *> packets = k.get_packets();
        for(Packet *& p : packets){
            if ((p -> get_tag() == 5)){
                std::string data = p -> raw();
                Tag5 * signer = new Tag5(data);
                // make sure key has signing material
                if ((signer -> get_pka() == 1) || // RSA
                    (signer -> get_pka() == 3) || // RSA
                    (signer -> get_pka() == 17)){ // DSA
                        return signer;
                }
                delete signer;
            }
        }
    }
    return NULL;
}

Tag13 * find_signer_id(PGP & k){
    std::vector <Packet *> packets = k.get_packets();
    for(Packet *& p : packets){
        if (p -> get_tag() == 13){
            std::string data = p -> raw();
            Tag13 * tag13 = new Tag13(data);
            return tag13;
        }
    }
    return NULL;
}

std::vector <mpz_class> pka_sign(std::string hashed_data, const uint8_t pka, const std::vector <mpz_class> & pub, const std::vector <mpz_class> & pri, const uint8_t h){
    if ((pka == 1) || (pka == 3)){ // RSA
        // RFC 4880 sec 5.2.2
        // If RSA, hash value is encoded using EMSA-PKCS1-v1_5
        hashed_data = EMSA_PKCS1_v1_5(h, hashed_data, pub[0].get_str(2).size() >> 3);
        return {RSA_sign(hashed_data, pri, pub)};
    }
    else if (pka == 17){ // DSA
        return DSA_sign(hashed_data, pri, pub);
    }
    else{
        std::cerr << "Error: Undefined or incorrect PKA number: " << (int) pka << std::endl;
        throw(1);
    }
    return {};
}

std::vector <mpz_class> pka_sign(const std::string & hashed_data, Tag5 * tag5, const std::string & passphrase, const uint8_t h){
    std::vector <mpz_class> pub = tag5 -> get_mpi();
    std::cout << "AAAAAAAAAAAA" << std::endl;
    std::vector <mpz_class> pri = decrypt_secret_key(tag5, passphrase);
    std::cout << "BBBBBBBBBBBB" << std::endl;
    return pka_sign(hashed_data, tag5 -> get_pka(), pub, pri, h);
}

Tag2 * create_sig_packet(const uint8_t type, Tag5 * tag5, ID * id){
    // Set up signature packet
    Tag2 * tag2 = new Tag2;
    tag2 -> set_version(4);
    tag2 -> set_pka(tag5 -> get_pka());
    tag2 -> set_type(type);
    tag2 -> set_hash(2);
    if (tag5 -> get_s2k()){
        tag2 -> set_hash(tag5 -> get_s2k() -> get_hash());
    }

    // Set Time
    Tag2Sub2 * tag2sub2 = new Tag2Sub2;
    tag2sub2 -> set_time(now());
    tag2 -> set_hashed_subpackets({tag2sub2});

    if (id){
        // Signer ID
        Tag2Sub28 * tag2sub28 = new Tag2Sub28;
        tag2sub28 -> set_signer(id -> raw());
        tag2 -> set_hashed_subpackets({tag2sub2, tag2sub28});
        delete tag2sub28;
    }

    // Set Key ID
    Tag2Sub16 * tag2sub16 = new Tag2Sub16;
    tag2sub16 -> set_keyid(tag5 -> get_keyid());
    tag2 -> set_unhashed_subpackets({tag2sub16});

    delete tag2sub2;
    delete tag2sub16;

    return tag2;
}

Tag2 * create_sig_packet(const uint8_t type, PGP & key){
    Tag5 * tag5 = find_signing_key(key);
    if (!tag5){
        std::cerr << "Error: No Private Key packet found." << std::endl;
        throw(1);
    }

    ID * id = find_signer_id(key);
    if (!id){
        std::cerr << "Error : No ID packet found." << std::endl;
        throw(1);
    }

    Tag2 * out = create_sig_packet(type, tag5, id);

    delete tag5;
    delete id;
    return out;
}

PGP sign_file(const std::string & data, PGP & key, const std::string & passphrase){
    if (key.get_ASCII_Armor() != 2){
        std::cerr << "Error: A private key is required." << std::endl;
        throw(1);
    }

    Tag5 * signer = find_signing_key(key);
    if (!signer){
        std::cerr << "Error: No Private Key packet found." << std::endl;
        throw(1);
    }

    Tag2 * sig = create_sig_packet(0x00, signer);

    std::string hashed_data = to_sign_00(data, sig);
    sig -> set_left16(hashed_data.substr(0, 2));
    sig -> set_mpi(pka_sign(hashed_data, signer, passphrase, sig -> get_hash()));

    PGP signature;
    signature.set_ASCII_Armor(5);
    std::vector <std::pair <std::string, std::string> > h = {std::pair <std::string, std::string>("Version", "cc")};
    signature.set_Armor_Header(h);
    signature.set_packets({sig});

    delete sig;
    delete signer;

    return signature;
}

PGP sign_file(std::ifstream & f, PGP & key, const std::string & passphrase){
    if (!f){
        std::cerr << "Error: Bad file." << std::endl;
        throw(1);
    }
    std::stringstream s;
    s << f.rdbuf();
    std::string data = s.str();

    return sign_file(data, key, passphrase);
}

PGPSignedMessage sign_message(const std::string & text, PGP & key, const std::string & passphrase){
    if (key.get_ASCII_Armor() != 2){
        std::cerr << "Error: A private key is required." << std::endl;
        throw(1);
    }

    Tag5 * signer = find_signing_key(key);
    if (!signer){
        std::cerr << "Error: No Private Key packet found." << std::endl;
        throw(1);
    }

    Tag2 * sig = create_sig_packet(0x01, signer);

    std::string hashed_data = to_sign_01(text, sig);
    sig -> set_left16(hashed_data.substr(0, 2));
    sig -> set_mpi(pka_sign(hashed_data, signer, passphrase, sig -> get_hash()));

    PGP signature;
    signature.set_ASCII_Armor(5);
    std::vector <std::pair <std::string, std::string> > h = {std::pair <std::string, std::string>("Version", "cc")};
    signature.set_Armor_Header(h);
    signature.set_packets({sig});

    PGPSignedMessage message;
    message.set_ASCII_Armor(6);
    h = {std::pair <std::string, std::string>("Hash", Hash_Algorithms.at(sig -> get_hash()))};
    message.set_Armor_Header(h);
    message.set_message(text);
    message.set_key(signature);

    delete sig;
    delete signer;

    return message;
}

Tag2 * sign_primary_key(const uint8_t cert, Tag5 * key, ID * id, const std::string & passphrase){
    if ((cert < 0x10) || (cert > 0x13)){
        std::cerr << "Error: Invalid Certification Value: " << (int) cert << std::endl;
        throw(1);
    }

    Tag2 * sig = create_sig_packet(cert, key);

    std::string hashed_data;
    // really not necessary since they all call to_sign_10
    if (cert == 0x10){
        hashed_data = to_sign_10(key, id, sig);
    }
    else if (cert == 0x11){
        hashed_data = to_sign_11(key, id, sig);
    }
    else if (cert == 0x12){
        hashed_data = to_sign_12(key, id, sig);
    }
    else if (cert == 0x13){
        hashed_data = to_sign_13(key, id, sig);
    }
    sig -> set_left16(hashed_data.substr(0, 2));
    sig -> set_mpi(pka_sign(hashed_data, key, passphrase, sig -> get_hash()));

    return sig;
}

Tag2 * sign_subkey(const uint8_t binding, Tag5 * primary, Tag7 * sub, const std::string & passphrase){
    if ((binding != 0x18) && (binding != 0x19)){
        std::cerr << "Error: Invalid Binding Signature Value: " << (int) binding << std::endl;
        throw(1);
    }

    Tag2 * sig = create_sig_packet(binding, primary);

    std::string hashed_data;
    if (binding == 0x18){
        hashed_data = to_sign_18(primary, sub, sig);
    }
    else if (binding == 0x19){
        hashed_data = to_sign_19(primary, sub, sig);
    }
    sig -> set_left16(hashed_data.substr(0, 2));
    sig -> set_mpi(pka_sign(hashed_data, primary, passphrase, sig -> get_hash()));

    return sig;
}

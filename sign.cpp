#include "sign.h"
Tag5 * find_signing_packet(PGP & k){
    std::vector <Packet *> packets = k.get_packets();
    for(Packet *& p : packets){
        if ((p -> get_tag() == 5) || (p -> get_tag() == 7)){
            std::string data = p -> raw();
            Tag5 * tag5 = new Tag5;
            tag5 -> read(data);
            if ((tag5 -> get_pka() == 1) ||
                (tag5 -> get_pka() == 3) ||
                (tag5 -> get_pka() == 17)){
                    return tag5;
            }
            delete tag5;
        }
    }
    return NULL;
}

Tag13 * find_signer_id(PGP & k){
    std::vector <Packet *> packets = k.get_packets();
    for(Packet *& p : packets){
        if (p -> get_tag() == 13){
            std::string data = p -> raw();
            Tag13 * tag13 = new Tag13;
            tag13 -> read(data);
            return tag13;
        }
    }
    return NULL;
}

std::vector <mpz_class> pka_sign(const std::string & hashed_data, uint8_t pka, std::vector <mpz_class> & pub, std::vector <mpz_class> & pri){
    if ((pka == 1) || (pka == 3)){ // RSA
        return {RSA_sign(hashed_data, pri, pub)};
    }
    else if (pka == 17){ // DSA
        return DSA_sign(hashed_data, pri, pub);
    }
    return {};
}

std::vector <mpz_class> pka_sign(const std::string & hashed_data, Tag5 * tag5, std::string pass){
    std::vector <mpz_class> pub = tag5 -> get_mpi();
    std::vector <mpz_class> pri = decrypt_secret_key(tag5, pass);
    if ((tag5 -> get_pka() == 1) || (tag5 -> get_pka() == 3)){
        return {RSA_sign(hashed_data, pri, pub)};
    }
    else if (tag5 -> get_pka() == 17){
        return DSA_sign(hashed_data, pri, pub);
    }
    return {};
}

Tag2 * create_sig_packet(const uint8_t type, PGP & key){
    BBS((mpz_class) (int) now());

    Tag5 * tag5 = find_signing_packet(key);
    Tag13 * tag13 = find_signer_id(key);

    // Set up signature packet
    Tag2 * tag2 = new Tag2;
    tag2 -> set_version(4);
    tag2 -> set_pka(tag5 -> get_pka());
    tag2 -> set_type(type);
    tag2 -> set_hash(2);

    std::vector <Subpacket *> subpackets;

    // Set Time
    subpackets = tag2 -> get_hashed_subpackets();
    Tag2Sub2 * tag2sub2 = new Tag2Sub2;
    tag2sub2 -> set_time(now());


    // Signer ID
    Tag2Sub28 * tag2sub28 = new Tag2Sub28;
    tag2sub28 -> set_signer(tag13 -> raw());
    tag2 -> set_hashed_subpackets({tag2sub2, tag2sub28});

    // Set Key ID
    subpackets = tag2 -> get_unhashed_subpackets();
    Tag2Sub16 * tag2sub16 = new Tag2Sub16;
    tag2sub16 -> set_keyid(tag5 -> get_keyid());
    tag2 -> set_unhashed_subpackets({tag2sub16});

    delete tag5;
    delete tag13;

    return tag2;
}

PGP sign_file(const std::string & data, PGP & key, const std::string & passphrase){
    Tag2 * tag2 = create_sig_packet(0x00, key);
    Tag5 * tag5 = find_signing_packet(key);
    std::string hashed_data = to_sign_00(data, tag2);
    tag2 -> set_left16(hashed_data.substr(0, 2));
    tag2 -> set_mpi(pka_sign(hashed_data, tag5, passphrase));

    PGP signature;
    signature.set_ASCII_Armor(5);
    std::vector <std::pair <std::string, std::string> > h = {std::pair <std::string, std::string>("Version", "cc")};
    signature.set_Armor_Header(h);
    signature.set_packets({tag2});

    delete tag2;
    delete tag5;

    return signature;
}

PGP sign_file(std::ifstream & f, PGP & key, const std::string & passphrase){
    if (!f){
        std::cerr << "Error: Bad file." << std::endl;
        exit(1);
    }
    std::stringstream s;
    s << f.rdbuf();
    std::string data = s.str();

    return sign_file(data, key, passphrase);
}

PGPMessage sign_message(const std::string & text, PGP & key, const std::string passphrase){
    Tag2 * tag2 = create_sig_packet(0x01, key);
    Tag5 * tag5 = find_signing_packet(key);

    std::string hashed_data = to_sign_01(text, tag2);
    tag2 -> set_left16(hashed_data.substr(0, 2));
    tag2 -> set_mpi(pka_sign(hashed_data, tag5, passphrase));

    PGP signature;
    signature.set_ASCII_Armor(5);
    std::vector <std::pair <std::string, std::string> > h = {std::pair <std::string, std::string>("Version", "cc")};
    signature.set_Armor_Header(h);
    signature.set_packets({tag2});

    PGPMessage message;
    message.set_ASCII_Armor(6);
    h = {std::pair <std::string, std::string>("Hash", Hash_Algorithms.at(tag2 -> get_hash()))};
    message.set_Armor_Header(h);
    message.set_message(text);
    message.set_key(signature);

    delete tag2;
    delete tag5;

    return message;
}

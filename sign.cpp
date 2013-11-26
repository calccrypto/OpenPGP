#include "sign.h"
Tag5 * find_signing_packet(PGP & k){
    std::vector <Packet *> packets = k.get_packets_pointers();
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
    std::vector <Packet *> packets = k.get_packets_pointers();
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

std::vector <integer> pka_sign(std::string hashed_data, Tag5 * tag5, std::string pass){
    std::vector <integer> pub = tag5 -> get_mpi();
    std::vector <integer> pri = decrypt_secret_key(tag5, pass);
    if ((tag5 -> get_pka() == 1) || (tag5 -> get_pka() == 3)){
        return {RSA_sign(hashed_data, pri, pub)};
    }
    else if (tag5 -> get_pka() == 17){
        return DSA_sign(hashed_data, pri, pub);
    }
    return {};
}

Tag2 * sign(uint8_t type, std::string hashed_data, Tag5 * tag5, std::string pass, Tag2 * tag2){
    if (!tag2){
        // Setup signature packet
        tag2 = new Tag2;
        tag2 -> set_version(4);
        tag2 -> set_pka(tag5 -> get_pka());
        tag2 -> set_type(type);
        tag2 -> set_hash(2);

        std::vector <Subpacket *> subpackets;

        // Set Time
        subpackets = tag2 -> get_hashed_subpackets_pointers();
        Tag2Sub2 * tag2sub2 = new Tag2Sub2;
        tag2sub2 -> set_time(now());
        subpackets.push_back(tag2sub2);
        tag2 -> set_hashed_subpackets(subpackets);

        // Set Key ID
        subpackets = tag2 -> get_unhashed_subpackets_pointers();
        Tag2Sub16 * tag2sub16 = new Tag2Sub16;
        tag2sub16 -> set_keyid(tag5 -> get_keyid());
        subpackets.push_back(tag2sub16);
        tag2 -> set_unhashed_subpackets(subpackets);
    }
    tag2 -> set_left16(hashed_data.substr(0, 2));
    tag2 -> set_mpi(pka_sign(hashed_data, tag5, pass));
    return tag2;
}

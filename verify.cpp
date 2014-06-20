#include "verify.h"

#include "PKCS1.h"

std::string find_keyid(Tag2::Ptr tag2){
    std::string out = "";
    // Search Subpackets
    // Most likely in unhashed subpackets
    std::vector <Subpacket::Ptr> subpackets = tag2 -> get_unhashed_subpackets();
    for(Subpacket::Ptr & s : subpackets){
        if (s -> get_type() == 16){
            std::string temp = s -> raw();
            Tag2Sub16 tag2sub16(temp);
            out = tag2sub16.get_keyid();
            break;
        }
    }
    // if not found in unhashed subpackets, search hashed subpackets
    if (!out.size()){
        subpackets = tag2 -> get_hashed_subpackets();
        for(Subpacket::Ptr & s : subpackets){
            if (s -> get_type() == 16){
                std::string temp = s -> raw();
                Tag2Sub16 tag2sub16(temp);
                out = tag2sub16.get_keyid();
                break;
            }
        }
    }
    return out;
}

std::vector <mpz_class> find_matching_pub_key(const std::string & keyid, PGP & key){
    std::vector <mpz_class> keys;
    std::vector <Packet::Ptr> packets = key.get_packets();
    for(Packet::Ptr & p : packets){
        if ((p -> get_tag() == 5) || (p -> get_tag() == 6) || (p -> get_tag() == 7) || (p -> get_tag() == 14)){
            std::string temp = p -> raw();
            Tag6::Ptr tag6(new Tag6);
            tag6 -> read(temp);
            if (tag6 -> get_keyid() == keyid){
                keys = tag6 -> get_mpi();
                break;
            }
        }
    }
    return keys;
}

bool pka_verify(std::string hashed_message, const uint8_t pka, const std::vector<mpz_class> & key, const std::vector<mpz_class> & signature, const uint8_t h){
    if ((pka == 1) || (pka == 3)){ // RSA
        hashed_message = EMSA_PKCS1_v1_5(h, hashed_message, key[0].get_str(2).size() >> 3);
        return RSA_verify(hashed_message, signature, key);
    }
    else if (pka == 17){ // DSA
        return DSA_verify(hashed_message, signature, key);
    }
    return false;
}

bool pka_verify(const std::string & hashed_message, Tag2::Ptr tag2, const std::vector <mpz_class> & key, const uint8_t h){
    std::vector <mpz_class> signature = tag2 -> get_mpi();
    return pka_verify(hashed_message, tag2 -> get_pka(), key, signature, h);
}

bool verify_file(const std::string & data, PGP & sig, PGP & key){
    if (sig.get_ASCII_Armor() != 5){
        throw std::runtime_error("Error: A signature packet is required.");
    }

    if ((key.get_ASCII_Armor() != 1) && (key.get_ASCII_Armor() != 2)){
        throw std::runtime_error("Error: A PGP key is required.");
    }

    std::string temp = sig.get_packets()[0] -> raw();
    Tag2::Ptr signature = std::make_shared<Tag2>(); signature -> read(temp);

    // Check left 16 bits
    std::string hash = to_sign_00(data, signature);
    if (hash.substr(0, 2) != signature -> get_left16()){
        throw std::runtime_error("Error: Hash and given left 16 bits of hash do not match.");
    }

    // find key id in signature
    std::string keyid = find_keyid(signature);
    if (!keyid.size()){
        throw std::runtime_error("Error: No Key ID subpacket found.");
    }

    // find matching public key packet and get the mpi
    std::vector <mpz_class> keys = find_matching_pub_key(keyid, key);
    if (!keys.size()){
        return false;
    }
    bool out = pka_verify(hash, signature, keys);
    return out;
}

bool verify_file(std::ifstream & f, PGP & sig, PGP & key){
    if (!f){
        throw std::runtime_error("Error: Bad file.");
    }
    std::stringstream s;
    s << f.rdbuf();
    std::string data = s.str();

    return verify_file(data, sig, key);
}

// Signature type 0x00 and 0x01
bool verify_message(PGPSignedMessage & message, PGP & key){
    if (message.get_key().get_ASCII_Armor() != 5){
        throw std::runtime_error("Error: A private key is required.");
    }

    if ((key.get_ASCII_Armor() != 1) && (key.get_ASCII_Armor() != 2)){
        throw std::runtime_error("Error: A PGP key is required.");
    }

    // Find key id from signature to match with public key
    std::string temp = message.get_key().get_packets()[0] -> raw();
    Tag2::Ptr signature = std::make_shared<Tag2>(); signature -> read(temp);

    // check left 16 bits
    std::string hash = to_sign_01(message.get_message(), signature);
    if (hash.substr(0, 2) != signature -> get_left16()){
        throw std::runtime_error("Error: Hash and given left 16 bits of hash do not match.");
    }

    // find key id in signature
    std::string keyid = find_keyid(signature);
    if (!keyid.size()){
        throw std::runtime_error("Error: No Key ID subpacket found.");
    }

    // find matching public key packet and get the mpi
    std::vector <mpz_class> keys = find_matching_pub_key(keyid, key);
    if (!keys.size()){
        return false;
    }

    // get string to check
    return pka_verify(hash, signature, keys);
}

// Signature Type 0x10 - 0x13
bool verify_signature(PGP & key, PGP & signer){
    if ((key.get_ASCII_Armor() != 1) && (key.get_ASCII_Armor() != 2)){
        throw std::runtime_error("Error: A PGP key is required.");
    }

    if ((signer.get_ASCII_Armor() != 1) && (signer.get_ASCII_Armor() != 2)){
        throw std::runtime_error("Error: A PGP key is required.");
    }

    std::vector <Packet::Ptr> packets = signer.get_packets();

    // find signing key
    std::vector <mpz_class> signing_key;
    for(Packet::Ptr& p : packets){
        if ((p -> get_tag() == 5) || (p -> get_tag() == 6)){
            std::string data = p -> raw();
            Tag6 tag6(data);
            if ((tag6.get_pka() == 1) || (tag6.get_pka() == 3) || (tag6.get_pka() == 17)){
                signing_key = tag6.get_mpi();
                break;
            }
        }
    }
    // if no signing key found, search subkeys
    if (!signing_key.size()){
        for(Packet::Ptr& p : packets){
            if ((p -> get_tag() == 7) || (p -> get_tag() == 14)){
                std::string data = p -> raw();
                Tag6 tag6(data);
                if ((tag6.get_pka() == 1) || (tag6.get_pka() == 3) || (tag6.get_pka() == 17)){
                    signing_key = tag6.get_mpi();
                    break;
                }
            }
        }
    }

    if (!signing_key.size()){
        throw std::runtime_error("Error: No key found.");
    }

    uint8_t version = 0;
    std::string k = "";
    std::string u = "";

    // set packets to signatures to verify
    packets = key.get_packets();

    bool out = true;

    Tag6::Ptr tag6;
    // for each packet
    for(Packet::Ptr& p : packets){
        std::string data = p -> raw();
        switch (p -> get_tag()){
            case 5: case 6: case 7: case 14:            // key packet
                tag6 = std::make_shared<Tag6>();
                tag6 -> read(data);
                k += overkey(tag6);                     // add current key packet to previous ones
                version = tag6 -> get_version();
                tag6.reset();
                break;
            case 13: case 17:                           // User packet
                {
                    ID::Ptr id;
                    if (p -> get_tag() == 13){
                        id = std::make_shared<Tag13>();
                    }
                    if (p -> get_tag() == 17){
                        id = std::make_shared<Tag17>();
                    }
                    id -> read(data);
                    u = certification(version, id);     // write over old user information
                }
                break;
            case 2:                                     // signature packet
                {
                    // copy packet data into signature packet
                    Tag2::Ptr tag2(new Tag2);
                    tag2 -> read(data);

                    // if signature is keybinding, erase the user information
                    if ((tag2 -> get_type() == 0x18) ||
                        (tag2 -> get_type() == 0x18)){
                        u = "";
                    }
                    // add hash contexts together and append trailer data
                    std::string with_trailer = addtrailer(k + u, tag2);
                    std::string hash = use_hash(tag2 -> get_hash(), with_trailer);
                    if (hash.substr(0, 2) == tag2 -> get_left16()){// quick signature check
                        out |= pka_verify(hash, tag2, signing_key);// proper signature check
                    }
                }
                break;
            default:
                {
                    std::stringstream s; s << (int) p -> get_tag();
                    throw std::runtime_error("Error: Incorrect packet type found: " + s.str());
                }
                break;
        }
    }
    return out;
}

bool verify_revoke(Tag6::Ptr key, Tag2::Ptr rev){
    return pka_verify(use_hash(rev -> get_hash(), addtrailer(overkey(key), rev)), rev, key -> get_mpi());
}

bool verify_revoke(PGP & key, PGP & rev){
    if ((key.get_ASCII_Armor() != 1) && (key.get_ASCII_Armor() != 2)){
        throw std::runtime_error("Error: A PGP key is required.");
    }

    if (rev.get_ASCII_Armor() != 1){
        throw std::runtime_error("Error: A revocation key is required.");
    }

    std::vector <Packet::Ptr> keys = key.get_packets();

    // copy revocation signature into tag2
    std::vector <Packet::Ptr> rev_pointers = rev.get_packets();

    // get revocation key; assume only 1 packet
    std::string rev_str = rev_pointers[0] -> raw();
    Tag2::Ptr revoke = std::make_shared<Tag2>(rev_str);

    // for each key packet
    for(Packet::Ptr & p : keys){
        // if the packet is a key packet
        if ((p -> get_tag() == 5) ||
            (p -> get_tag() == 6) ||
            (p -> get_tag() == 7) ||
            (p -> get_tag() == 14)){

            // copy key into Tag 6
            std::string key_str = p -> raw();
            Tag6::Ptr tag6 = std::make_shared<Tag6>(key_str);

            if (verify_revoke(tag6, revoke)){
                return true;
            }
        }
    }
    return false;
}

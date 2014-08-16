#include "revoke.h"
bool check_revoked(const std::vector <Packet::Ptr> & packets, const std::string & keyid){
    for(Packet::Ptr const & p: packets){
        // if a signature packet
        if (p -> get_tag() == 2){
            std::string raw = p -> raw();
            Tag2 tag2(raw);
            for(Subpacket::Ptr const & s: tag2.get_unhashed_subpackets()){
                if (s -> get_type() == 16){
                    raw = s -> raw();
                    Tag2Sub16 tag2sub16(raw);
                    // check that this signature packet is for the public key
                    if (tag2sub16.get_keyid() == keyid){
                        if ((tag2.get_type() == 0x20) || (tag2.get_type() == 0x28)){
                            return true;
                        }
                    }
                }
            }
            for(Subpacket::Ptr const & s: tag2.get_hashed_subpackets()){
                if (s -> get_type() == 16){
                    raw = s -> raw();
                    Tag2Sub16 tag2sub16(raw);
                    // check that this signature packet is for the public key
                    if (tag2sub16.get_keyid() == keyid){
                        if ((tag2.get_type() == 0x20) || (tag2.get_type() == 0x28)){
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}

bool check_revoked(const PGPPublicKey & pub, const std::string & keyid){
    return check_revoked(pub.get_packets(), keyid);
}

bool check_revoked(const PGPSecretKey & pri, const std::string & keyid){
    return check_revoked(pri.get_packets(), keyid);
}

Tag2::Ptr revoke_primary_key_cert(PGPSecretKey & pri, const std::string & passphrase, const uint8_t code, const std::string & reason){
    if (pri.get_ASCII_Armor() != 2){
        throw std::runtime_error("Error: A private key is required for the first argument.");
    }

    Tag5::Ptr key = find_signing_key(pri, 5);
    if (!key){
        throw std::runtime_error("Error: No Secret Key packet found.");
    }

    Tag2::Ptr sig = create_sig_packet(0x20, pri);

    // add revocation subpacket
    std::vector <Tag2Subpacket::Ptr> hashed_subpackets = sig -> get_hashed_subpackets_clone();
    Tag2Sub29::Ptr revoke = std::make_shared<Tag2Sub29>();
    revoke -> set_code(code);
    revoke -> set_reason(reason);
    hashed_subpackets.push_back(revoke);
    sig -> set_hashed_subpackets(hashed_subpackets);

    // set signature data
    std::string hashed_data = to_sign_20(key, sig);
    sig -> set_left16(hashed_data.substr(0, 2));
    sig -> set_mpi(pka_sign(hashed_data, key, passphrase, sig -> get_hash()));

    key.reset();
    revoke.reset();

    return sig;
}

PGPPublicKey revoke_primary_key_cert_key(PGPSecretKey & pri, const std::string & passphrase, const uint8_t code, const std::string & reason){
    Tag2::Ptr sig = revoke_primary_key_cert(pri, passphrase, code, reason);

    PGPPublicKey signature;
    signature.set_ASCII_Armor(1);
    std::vector <std::pair <std::string, std::string> > h = {std::make_pair("Version", "cc"),
                                                             std::make_pair("Comment", "Revocation Certificate")};
    signature.set_Armor_Header(h);
    signature.set_packets({sig});

    sig.reset();
    
    return signature;
}

Tag2::Ptr revoke_subkey_cert(PGPSecretKey & pri, const std::string & passphrase, const uint8_t code, const std::string & reason){
    if (pri.get_ASCII_Armor() != 2){
        throw std::runtime_error("Error: A private key is required for the first argument.");
    }

    Tag5::Ptr signer = find_signing_key(pri, 5);
    if (!signer){
        throw std::runtime_error("Error: Private signing key not found");
    }

    // find subkey
    Tag7::Ptr key = nullptr;
    std::vector <Packet::Ptr> packets = pri.get_packets();
    for(Packet::Ptr const & p : packets){
        if (p -> get_tag() == 7){
            std::string data = p -> raw();
            key = std::make_shared<Tag7>(data);
            break;
        }
    }

    if (!key){
        throw std::runtime_error("Error: No Secret Subkey packet found.");
    }

    Tag2::Ptr sig = create_sig_packet(0x28, signer);

    // add revocation subpacket
    std::vector <Tag2Subpacket::Ptr> hashed_subpackets = sig -> get_hashed_subpackets_clone();
    Tag2Sub29::Ptr revoke = std::make_shared<Tag2Sub29>();
    revoke -> set_code(code);
    revoke -> set_reason(reason);
    hashed_subpackets.push_back(revoke);
    sig -> set_hashed_subpackets(hashed_subpackets);

    // set signature data
    std::string hashed_data = to_sign_28(key, sig);
    sig -> set_left16(hashed_data.substr(0, 2));
    sig -> set_mpi(pka_sign(hashed_data, signer, passphrase, sig -> get_hash()));

    signer.reset();
    key.reset();
    revoke.reset();

    return sig;
}

PGPPublicKey revoke_subkey_cert_key(PGPSecretKey & pri, const std::string & passphrase, const uint8_t code, const std::string & reason){
    Tag2::Ptr sig = revoke_subkey_cert(pri, passphrase, code, reason);

    PGPPublicKey signature;
    signature.set_ASCII_Armor(1);
    std::vector <std::pair <std::string, std::string> > h = {std::make_pair("Version", "cc"),
                                                             std::make_pair("Comment", "Revocation Certificate")};
    signature.set_Armor_Header(h);
    signature.set_packets({sig});

    sig.reset();

    return signature;
}

PGPPublicKey revoke_uid(PGPPublicKey & pub, PGPSecretKey & pri, const std::string passphrase, const uint8_t code, const std::string & reason){
    if (pub.get_ASCII_Armor() != 1){
        throw std::runtime_error("Error: A public key is required for the first argument.");
    }
    if (pri.get_ASCII_Armor() != 2){
        throw std::runtime_error("Error: A private key is required for the second argument.");
    }

    Tag5::Ptr signer = find_signing_key(pri, 5);
    if (!signer){
        throw std::runtime_error("Error: Private signing key not found");
    }

    // find subkey
    Tag7::Ptr key = nullptr;
    std::vector <Packet::Ptr> packets = pri.get_packets();
    for(Packet::Ptr const & p : packets){
        if (p -> get_tag() == 7){
            std::string data = p -> raw();
            key = std::make_shared<Tag7>(data);
            break;
        }
    }

    if (!key){
        throw std::runtime_error("Error: No Secret Subkey packet found.");
    }

    ID::Ptr uid = find_user_id(pri);
    if (!uid){
        throw std::runtime_error("Error: No User ID packet found.");
    }

    Tag2::Ptr sig = create_sig_packet(0x30, signer);

    // add revocation subpacket
    std::vector <Tag2Subpacket::Ptr> hashed_subpackets = sig -> get_hashed_subpackets_clone();
    Tag2Sub29::Ptr revoke = std::make_shared<Tag2Sub29>();
    revoke -> set_code(code);
    revoke -> set_reason(reason);
    hashed_subpackets.push_back(revoke);
    sig -> set_hashed_subpackets(hashed_subpackets);

    // set signature data
    std::string hashed_data = to_sign_30(key, uid, sig);
    sig -> set_left16(hashed_data.substr(0, 2));
    sig -> set_mpi(pka_sign(hashed_data, signer, passphrase, sig -> get_hash()));

    // Create output key
    PGPPublicKey revoked(pub);
    std::vector <Packet::Ptr> old_packets = pub.get_packets_clone();
    std::vector <Packet::Ptr> new_packets;

    unsigned int i = 0;
    // push all packets up to and including revoked packet into new packets
    do{
        new_packets.push_back(old_packets[i]);
    }
    while ((i < old_packets.size()) && (old_packets[i++] -> get_tag() != 13));

    // append revocation signature to key
    new_packets.push_back(sig);

    // append rest of packets
    while (i < old_packets.size()){
        new_packets.push_back(old_packets[i++]);
    }
    revoked.set_packets(new_packets);

    signer.reset();
    key.reset();
    uid.reset();
    sig.reset();

    return revoked;
}

PGPPublicKey revoke_key(PGPSecretKey & pri, const std::string & passphrase, const uint8_t code, const std::string & reason){
    if (pri.get_ASCII_Armor() != 2){
        throw std::runtime_error("Error: A private key is required for the second argument.");
    }

    std::vector <Packet::Ptr> packets = pri.get_packets();

    Tag2::Ptr rev = revoke_primary_key_cert(pri, passphrase, code, reason);

    std::string raw = packets[0] -> raw();
    Tag6::Ptr primary = std::make_shared<Tag6>(raw);

    // assume first packet is primary key, and add a revocation signature as the next packet
    std::vector <Packet::Ptr> new_packets = {primary, rev};
    // clone the rest of the packets
    for(unsigned int i = 1; i < packets.size(); i++){
        new_packets.push_back(packets[i] -> clone());
    }

    PGPPublicKey revoked;
    revoked.set_ASCII_Armor(1); // public key
    revoked.set_Armor_Header(pri.get_Armor_Header());
    revoked.set_packets(new_packets);

    primary.reset();
    new_packets.clear();

    return revoked;
}

PGPPublicKey revoke_subkey(PGPSecretKey & pri, const std::string & passphrase, const uint8_t code, const std::string & reason){
    if (pri.get_ASCII_Armor() != 2){
        throw std::runtime_error("Error: A private key is required for the second argument.");
    }

    std::vector <Packet::Ptr> packets = pri.get_packets();

    Tag2::Ptr rev = revoke_subkey_cert(pri, passphrase, code, reason);

    // assume first packet is primary key
    std::vector <Packet::Ptr> new_packets;

    // clone all packets up to and including the subkey
    unsigned int i = 0;
    do{
        new_packets.push_back(packets[i] -> clone());
    }
    while (packets[i++] -> get_tag() != 7);

    // append the revocation key
    new_packets.push_back(rev);

    // clone the rest of the key
    while (i < packets.size()){
        new_packets.push_back(packets[i++] -> clone());
    }

    PGPPublicKey revoked;
    revoked.set_ASCII_Armor(1); // public key
    revoked.set_Armor_Header(pri.get_Armor_Header());
    revoked.set_packets(new_packets);

    new_packets.clear();

    return revoked;
}

PGPPublicKey revoke_with_cert(const PGPPublicKey & pub, PGPPublicKey & revoke){
    if (pub.get_ASCII_Armor() != 1){
        throw std::runtime_error("Error: A public key is required.");
    }

    if (revoke.get_ASCII_Armor() != 1){
        throw std::runtime_error("Error: A revocation signature is required.");
    }

    // only expects 1 signature packet
    if (!revoke.get_packets().size()){
        throw std::runtime_error("Error: No packets found in revocation key.");
    }
    if (revoke.get_packets().size() > 1){
        std::cerr << "Warning: Multiple packets found. Only reading first packet." << std::endl;
    }
    if (revoke.get_packets()[0] -> get_tag() != 2){
        throw std::runtime_error("Error: Packet is not a signature packet");
    }

    std::string raw = revoke.get_packets()[0] -> raw();
    Tag2::Ptr tag2 = std::make_shared<Tag2>(raw);

    if ((tag2 -> get_type() != 0x20) && (tag2 -> get_type() != 0x28)){
        std::stringstream s; s << static_cast <unsigned int> (tag2->get_type());
        throw std::runtime_error("Error: Invalid signature type found: " + s.str());
    }

    // which packet to look for
    uint8_t which = (tag2 -> get_type() == 0x20)?6:14;

    std::string r_keyid = tag2 -> get_keyid();
    std::string k_keyid = "";

    if (!r_keyid.size()){
        throw std::runtime_error("Error: No key id found.");
    }

    // find key with key id
    for(Packet::Ptr const & p: pub.get_packets()){
        if (p -> get_tag() == which){
            raw = p -> raw();
            Tag6 tag6(raw);
            k_keyid = tag6.get_keyid();
            break;
        }
    }

    if (r_keyid != k_keyid){
        throw std::runtime_error("Error: Revocation Certificate does not revoke this Public Key.");
    }

    if (!verify_revoke(pub, revoke)){
        throw std::runtime_error("Error: This revocation certificate was not signed by this key.");
    }

    // Create output key
    PGPPublicKey revoked(pub);
    std::vector <Packet::Ptr> old_packets = pub.get_packets_clone();
    std::vector <Packet::Ptr> new_packets;

    unsigned int i = 0;
    // push all packets up to and including revoked packet into new packets
    do{
        new_packets.push_back(old_packets[i]);
    }
    while ((i < old_packets.size()) && (old_packets[i++] -> get_tag() != which));

    // append revocation signature to key
    new_packets.push_back(tag2);
    // append rest of packets
    while (i < old_packets.size()){
        new_packets.push_back(old_packets[i++]);
    }
    revoked.set_packets(new_packets);

    // clear out data
    tag2.reset();
    old_packets.clear();
    new_packets.clear();

    return revoked;
}

PGPPublicKey revoke_with_cert(const PGPSecretKey & pri, PGPPublicKey & revoke){
    PGPPublicKey pub(pri);
    return revoke_with_cert(pub, revoke);
}

#include "sign.h"
Tag5::Ptr find_signing_key(PGP & k){
    if (k.get_ASCII_Armor() == 2){
        std::vector <Packet::Ptr> packets = k.get_packets();
        for(Packet::Ptr & p : packets){
            if ((p -> get_tag() == 5) || (p -> get_tag() == 7)){
                std::string data = p -> raw();
                Tag5::Ptr signer(new Tag5(data));
                // make sure key has signing material
                if ((signer -> get_pka() == 1) || // RSA
                    (signer -> get_pka() == 3) || // RSA
                    (signer -> get_pka() == 17)){ // DSA
                        return signer;
                }
            }
        }
    }
    return Tag5::Ptr();
}

ID::Ptr find_signer_id(PGP & k){
    std::vector <Packet::Ptr> packets = k.get_packets();
    for(Packet::Ptr & p : packets){
        if (p -> get_tag() == 13){
            std::string data = p -> raw();
            Tag13::Ptr tag13(new Tag13(data));
            return tag13;
        }
        if (p -> get_tag() == 17){
            std::string data = p -> raw();
            Tag17::Ptr tag17(new Tag17(data));
            return tag17;
        }
    }
    return ID::Ptr();
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
        std::stringstream s; s << static_cast <int> (pka);
        throw std::runtime_error("Error: Undefined or incorrect PKA number: " + s.str());
    }
    return {};
}

std::vector <mpz_class> pka_sign(const std::string & hashed_data, Tag5::Ptr tag5, const std::string & passphrase, const uint8_t h){
    std::vector <mpz_class> pub = tag5 -> get_mpi();
    std::vector <mpz_class> pri = decrypt_secret_key(tag5, passphrase);
    return pka_sign(hashed_data, tag5 -> get_pka(), pub, pri, h);
}

Tag2::Ptr create_sig_packet(const uint8_t type, Tag5::Ptr tag5, ID::Ptr id){
    // Set up signature packet
    Tag2::Ptr tag2(new Tag2);
    tag2 -> set_version(4);
    tag2 -> set_pka(tag5 -> get_pka());
    tag2 -> set_type(type);
    tag2 -> set_hash(2);
    if (tag5 -> get_s2k()){
        tag2 -> set_hash(tag5 -> get_s2k() -> get_hash());
    }

    // Set Time
    Tag2Sub2::Ptr tag2sub2 = std::make_shared<Tag2Sub2>();
    tag2sub2 -> set_time(now());
    tag2 -> set_hashed_subpackets({tag2sub2});

    if (id){
        // Signer ID
        Tag2Sub28::Ptr tag2sub28 = std::make_shared<Tag2Sub28>();
        tag2sub28 -> set_signer(id -> raw());
        tag2 -> set_hashed_subpackets({tag2sub2, tag2sub28});
    }

    // Set Key ID
    Tag2Sub16::Ptr tag2sub16 = std::make_shared<Tag2Sub16>();
    tag2sub16 -> set_keyid(tag5 -> get_keyid());
    tag2 -> set_unhashed_subpackets({tag2sub16});

    return tag2;
}

Tag2::Ptr create_sig_packet(const uint8_t type, PGP & key){
    Tag5::Ptr tag5 = find_signing_key(key);
    if (!tag5){
        throw std::runtime_error("Error: No Private Key packet found.");
    }

    ID::Ptr id = find_signer_id(key);
    if (!id){
        throw std::runtime_error("Error: No ID packet found.");
    }

    Tag2::Ptr out = create_sig_packet(type, tag5, id);

    return out;
}

PGP sign_file(const std::string & data, PGP & key, const std::string & passphrase){
    if (key.get_ASCII_Armor() != 2){
        throw std::runtime_error("Error: A private key is required.");
    }

    Tag5::Ptr signer = find_signing_key(key);
    if (!signer){
        throw std::runtime_error("Error: No Private Key packet found.");
    }

    // Check if key has been revoked
    if (check_revoked(key, signer -> get_keyid())){
        throw std::runtime_error("Error: Key " + hexlify(signer -> get_keyid()) + " has been revoked. Nothing done.");
    }

    Tag2::Ptr sig = create_sig_packet(0x00, signer);

    std::string hashed_data = to_sign_00(data, sig);
    sig -> set_left16(hashed_data.substr(0, 2));
    sig -> set_mpi(pka_sign(hashed_data, signer, passphrase, sig -> get_hash()));

    PGP signature;
    signature.set_ASCII_Armor(5);
    std::vector <std::pair <std::string, std::string> > h = {std::pair <std::string, std::string>("Version", "cc")};
    signature.set_Armor_Header(h);
    signature.set_packets({sig});

    return signature;
}

PGP sign_file(std::ifstream & f, PGP & key, const std::string & passphrase){
    if (!f){
        throw std::runtime_error("Error: Bad file.");
    }
    std::stringstream s; s << f.rdbuf();
    return sign_file(s.str(), key, passphrase);
}

PGPSignedMessage sign_message(const std::string & text, PGP & key, const std::string & passphrase){
    if (key.get_ASCII_Armor() != 2){
        throw std::runtime_error("Error: A private key is required.");
    }

    Tag5::Ptr signer = find_signing_key(key);
    if (!signer){
        throw std::runtime_error("Error: No Private Key packet found.");
    }

    Tag2::Ptr sig = create_sig_packet(0x01, signer);

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

    return message;
}

Tag2::Ptr standalone_signature(Tag5::Ptr key, Tag2::Ptr src, const std::string & passphrase){
    Tag2::Ptr sig = create_sig_packet(0x02, key);
    std::string hashed_data = to_sign_02(src);
    sig -> set_left16(hashed_data.substr(0, 2));
    sig -> set_mpi(pka_sign(hashed_data, key, passphrase, src -> get_hash()));

    return sig;
}

Tag2::Ptr sign_primary_key(Tag5::Ptr key, ID::Ptr id, const std::string & passphrase, const uint8_t cert){
    if ((cert < 0x10) || (cert > 0x13)){
        std::stringstream s; s << static_cast <int> (cert);
        throw std::runtime_error("Error: Invalid Certification Value: " + s.str());
    }

    Tag2::Ptr sig = create_sig_packet(cert, key);
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

PGP sign_primary_key(PGP & signee, PGP & signer, const std::string & passphrase, const uint8_t cert){
    if (signee.get_ASCII_Armor() != 1){
        throw std::runtime_error("Error: Signee key should be public.");
    }

    if (signer.get_ASCII_Armor() != 2){
        throw std::runtime_error("Error: Signer key should be private.");
    }

    if ((cert < 0x10) || (cert > 0x13)){
        std::stringstream s; s << static_cast <int> (cert);
        throw std::runtime_error("Error: Invalid Certification Value: " + s.str());
    }


    Tag6::Ptr signee_primary_key;
    ID::Ptr signee_id;

    // find primary key; generally packet[0]
    std::vector <Packet::Ptr> signee_packets = signee.get_packets_clone();
    unsigned int i = 0;
    for(i = 0; i < signee_packets.size(); i++){
        if (signee_packets[i] -> get_tag() == 6){
            std::string raw = signee_packets[i] -> raw();
            signee_primary_key = std::make_shared<Tag6>(raw);
            break;
        }
    }

    // move pointer to user id
    i++;

    // check for user id packet
    if (!(i < signee_packets.size())){
        throw std::runtime_error("Error: No packets following Primary Key.");
    }
    if ((signee_packets[i] -> get_tag() != 13) && (signee_packets[i] -> get_tag() != 17)){
        throw std::runtime_error("Error: No User ID packet following Primary Key");
    }

    // get signee user id packet
    std::string raw_id = signee_packets[i] -> raw();
    if (signee_packets[i] -> get_tag() == 13){
        signee_id = std::make_shared<Tag13>(raw_id);
    }
    else if (signee_packets[i] -> get_tag() == 17){
        signee_id = std::make_shared<Tag17>(raw_id);
    }

    // move i to after primary key signature
    i++;

    // get signer's signing packet
    Tag5::Ptr signer_signing_key = find_signing_key(signer);

    // check if the signer has alreaady signed this key
    unsigned int j = i;
    while ((j < signee_packets.size()) && (signee_packets[j] -> get_tag() == 2)){
        std::string raw = signee_packets[j++] -> raw();
        Tag2 tag2(raw);
        // search unhashed subpackets first (key id is usually in there)
        for(Subpacket::Ptr & s : tag2.get_unhashed_subpackets()){
            if (s -> get_type() == 16){
                raw = s -> raw();
                Tag2Sub16 tag2sub16(raw);
                if (tag2sub16.get_keyid() == signer_signing_key -> get_keyid()){
                    std::cerr << "Warning: Key " << signee << " has already been signed by this key " << signer << ". Nothing done. " << std::endl;
                    return signee;
                }
            }
        }

        // search hashed subpackets
        for(Subpacket::Ptr & s : tag2.get_hashed_subpackets()){
            if (s -> get_type() == 16){
                raw = s -> raw();
                Tag2Sub16 tag2sub16(raw);
                if (tag2sub16.get_keyid() == signer_signing_key -> get_keyid()){
                    std::cerr << "Warning: Key " << signee << " has already been signed by this key " << signer << std::endl;
                    return signee;
                }
            }
        }
    }

    // sign key
    Tag2::Ptr sig = create_sig_packet(cert, signer_signing_key);
    std::string hashed_data;
    // really not necessary since they all call to_sign_10
    if (cert == 0x10){
        hashed_data = to_sign_10(signee_primary_key, signee_id, sig);
    }
    else if (cert == 0x11){
        hashed_data = to_sign_11(signee_primary_key, signee_id, sig);
    }
    else if (cert == 0x12){
        hashed_data = to_sign_12(signee_primary_key, signee_id, sig);
    }
    else if (cert == 0x13){
        hashed_data = to_sign_13(signee_primary_key, signee_id, sig);
    }

    sig -> set_left16(hashed_data.substr(0, 2));
    sig -> set_mpi(pka_sign(hashed_data, signer_signing_key, passphrase, sig -> get_hash()));

    // Create output key
    PGP out(signee);
    std::vector <Packet::Ptr> out_packets;

    j = 0;
    // push all packets up to and including out packet into new packets
    do{
        out_packets.push_back(signee_packets[j]);
    }
    while ((j < signee_packets.size()) && (j++ < i));

    // append revocation signature to key
    out_packets.push_back(sig);

    // append rest of packets
    while (j < signee_packets.size()){
        out_packets.push_back(signee_packets[j++]);
    }
    out.set_packets(out_packets);

    return out;
}

Tag2::Ptr sign_subkey(Tag5::Ptr primary, Tag7::Ptr sub, const std::string & passphrase, const uint8_t binding){
    if ((binding != 0x18) && (binding != 0x19)){
        std::stringstream s; s << static_cast <int> (binding);
        throw std::runtime_error("Error: Invalid Binding Signature Value: " + s.str());
    }

    Tag2::Ptr sig = create_sig_packet(binding, primary);

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

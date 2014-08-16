#include "sign.h"

// possible to mess up
ID::Ptr find_user_id(const PGPSecretKey & k){
    for(Packet::Ptr const & p : k.get_packets()){
        if (p -> get_tag() == 13){
            std::string raw = p -> raw();
            return std::make_shared <Tag13> (raw);
        }
        if (p -> get_tag() == 17){
            std::string raw = p -> raw();
            return std::make_shared <Tag17> (raw);
        }
    }
    return nullptr;
}

std::vector <PGPMPI> pka_sign(const std::string & digest, const uint8_t pka, const std::vector <PGPMPI> & pub, const std::vector <PGPMPI> & pri, const uint8_t h){
    if ((pka == 1) || (pka == 3)){ // RSA
        // RFC 4880 sec 5.2.2
        // If RSA, hash value is encoded using EMSA-PKCS1-v1_5
        std::string encoded = EMSA_PKCS1_v1_5(h, digest, bitsize(pub[0]) >> 3);
        return {RSA_sign(encoded, pri, pub)};
    }
    else if (pka == 17){ // DSA
        return DSA_sign(digest, pri, pub);
    }
    else{
        std::stringstream s; s << static_cast <unsigned int> (pka);
        throw std::runtime_error("Error: Undefined or incorrect PKA number: " + s.str());
    }
    return {};
}

std::vector <PGPMPI> pka_sign(const std::string & digest, const Tag5::Ptr & tag5, const std::string & passphrase, const uint8_t h){
    std::vector <PGPMPI> pub = tag5 -> get_mpi();
    std::vector <PGPMPI> pri = decrypt_secret_key(tag5, passphrase);
    return pka_sign(digest, tag5 -> get_pka(), pub, pri, h);
}

Tag2::Ptr create_sig_packet(const uint8_t type, const Tag5::Ptr & tag5, const ID::Ptr & id, const uint8_t hash){
    // Set up signature packet
    Tag2::Ptr tag2 = std::make_shared<Tag2>();
    tag2 -> set_version(4);
    tag2 -> set_pka(tag5 -> get_pka());
    tag2 -> set_type(type);
    tag2 -> set_hash(hash); // default SHA1
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
        tag2sub28.reset();
    }

    // Set Key ID
    Tag2Sub16::Ptr tag2sub16 = std::make_shared<Tag2Sub16>();
    tag2sub16 -> set_keyid(tag5 -> get_keyid());
    tag2 -> set_unhashed_subpackets({tag2sub16});

    tag2sub2.reset();
    tag2sub16.reset();

    return tag2;
}

Tag2::Ptr create_sig_packet(const uint8_t type, const PGPSecretKey & pri, const uint8_t hash){
    Tag5::Ptr tag5 = find_signing_key(pri, 5);
    if (!tag5){
        throw std::runtime_error("Error: No Private Key packet found.");
    }

    ID::Ptr id = find_user_id(pri);
    if (!id){
        throw std::runtime_error("Error: No ID packet found.");
    }

    Tag2::Ptr out = create_sig_packet(type, tag5, id, hash);

    tag5.reset();
    id.reset();

    return out;
}

Tag2::Ptr sign_00(const PGPSecretKey & pri, const std::string & passphrase, const std::string & data, const uint8_t hash){
    if (pri.get_ASCII_Armor() != 2){
        throw std::runtime_error("Error: A private key is required.");
    }

    Tag5::Ptr signer = find_signing_key(pri, 5);
    if (!signer){
        throw std::runtime_error("Error: No Private Key for signing found.");
    }

    // Check if key has been revoked
    if (check_revoked(pri, signer -> get_keyid())){
        throw std::runtime_error("Error: Key " + hexlify(signer -> get_keyid()) + " has been revoked. Nothing done.");
    }

    // create Signature Packet
    Tag2::Ptr sig = create_sig_packet(0x00, pri, hash);
    std::string digest = to_sign_00(data, sig);
    sig -> set_left16(digest.substr(0, 2));
    sig -> set_mpi(pka_sign(digest, signer, passphrase, sig -> get_hash()));

    signer.reset();

    return sig;
}

PGPDetachedSignature sign_detach(const PGPSecretKey & pri, const std::string & passphrase, const std::string & data, const uint8_t hash){
    PGPDetachedSignature signature;
    signature.set_ASCII_Armor(5);
    std::vector <std::pair <std::string, std::string> > h = {std::pair <std::string, std::string> ("Version", "cc")};
    signature.set_Armor_Header(h);
    signature.set_packets({sign_00(pri, passphrase, data, hash)});

    return signature;
}

PGPDetachedSignature sign_detach(const PGPSecretKey & pri, const std::string & passphrase, std::ifstream & f, const uint8_t hash){
    if (!f){
        throw std::runtime_error("Error: Bad file.");
    }
    std::stringstream s; s << f.rdbuf();
    return sign_detach(pri, passphrase, s.str(), hash);
}

PGPMessage sign_message(const PGPSecretKey & pri, const std::string & passphrase, const std::string & filename, const std::string & data, const uint8_t hash, const uint8_t compress){
    // find signing key
    Tag5::Ptr tag5 = find_signing_key(pri, 5);
    if (!tag5){
        throw std::runtime_error("Error: No signing key found.");
    }

    // find matching signature packet
    Tag2::Ptr keysig = nullptr;
    for(Packet::Ptr const & p : pri.get_packets()){
        if (p -> get_tag() == 2){
            std::string data = p -> raw();
            Tag2 * temp = new Tag2(data);
            if (temp -> get_keyid() == tag5 -> get_keyid()){
                keysig = std::shared_ptr <Tag2> (temp);
                break;
            }
            delete temp;
        }
    }

    if (!keysig){
        throw std::runtime_error("Error: Cannot find matching Signature Packet for Signing Key " + hexlify(tag5 -> get_keyid()) + ".");
    }

    // find ID packet
    // need better search method; possible to mess up
    ID::Ptr id = find_user_id(pri);
    if (!id){
        throw std::runtime_error("Error: Cannot find Signing Key ID packet.");
    }

    // create One-Pass Signature Packet
    Tag4::Ptr tag4(new Tag4);
    tag4 -> set_type(0);
    tag4 -> set_hash(hash);
    tag4 -> set_pka(tag5 -> get_pka());
    tag4 -> set_keyid(keysig -> get_keyid());
    tag4 -> set_nested(1); // 1 for no nesting

    // put source data into Literal Data Packet
    Tag11::Ptr tag11(new Tag11);
    tag11 -> set_format('b');
    tag11 -> set_filename(filename);
    tag11 -> set_time(now());
    tag11 -> set_literal(data);

    // sign data
    Tag2::Ptr tag2 = create_sig_packet(0, pri, hash);
    std::string digest = to_sign_00(tag11 -> get_literal(), tag2);
    tag2 -> set_left16(digest.substr(0, 2));
    tag2 -> set_mpi(pka_sign(digest, tag5, passphrase, hash));

    // put everything together
    PGPMessage signature;
    signature.set_ASCII_Armor(5);
    std::vector <std::pair <std::string, std::string> > h = {std::pair <std::string, std::string> ("Version", "cc")};
    signature.set_Armor_Header(h);
    signature.set_packets({tag4, tag11, tag2});

    if (compress){ // only use a Compressed Data Packet if compression was used; don't bother for uncompressed data
        Tag8 tag8;
        tag8.set_data(signature.raw());
        tag8.set_comp(compress);
        std::string raw = tag8.write(2);
        signature = PGPMessage(raw);
    }

    tag4.reset();
    tag11.reset();
    tag2.reset();

    return signature;
}

PGPMessage sign_message(const PGPSecretKey & pri, const std::string & passphrase, const std::string & filename, const uint8_t hash, const uint8_t compress){
    std::ifstream f(filename.c_str(), std::ios::binary);
    if (!f){
        throw std::runtime_error("Error: Unable to open file '" + filename + "'.");
    }
    std::stringstream s; s << f.rdbuf();
    return sign_message(pri, passphrase, filename, s.str(), hash);
}

PGPMessage sign_message(const PGPSecretKey & pri, const std::string & passphrase,  const std::string & filename, std::ifstream & f, const uint8_t hash, const uint8_t compress){
    if (!f){
        throw std::runtime_error("Error: Bad file.");
    }
    std::stringstream s; s << f.rdbuf();
    return sign_message(pri, passphrase, filename, s.str(), hash);
}

PGPCleartextSignature sign_cleartext(const PGPSecretKey & pri, const std::string & passphrase, const std::string & text, const uint8_t hash){
    if (pri.get_ASCII_Armor() != 2){
        throw std::runtime_error("Error: A private key is required.");
    }

    Tag5::Ptr signer = find_signing_key(pri, 5);
    if (!signer){
        throw std::runtime_error("Error: No Private Key packet found.");
    }

    // create signature
    Tag2::Ptr sig = create_sig_packet(0x01, signer, nullptr, hash);
    std::string digest = to_sign_01(text, sig);
    sig -> set_left16(digest.substr(0, 2));
    sig -> set_mpi(pka_sign(digest, signer, passphrase, sig -> get_hash()));

    // put signature into Deatched Signature
    PGPDetachedSignature signature;
    signature.set_ASCII_Armor(5);
    std::vector <std::pair <std::string, std::string> > h = {std::pair <std::string, std::string> ("Version", "cc")};
    signature.set_Armor_Header(h);
    signature.set_packets({sig});

    // put signature under cleartext
    PGPCleartextSignature message;
    h = {std::pair <std::string, std::string>("Hash", Hash_Algorithms.at(sig -> get_hash()))};
    message.set_Armor_Header(h);
    message.set_message(text);
    message.set_sig(signature);

    signer.reset();
    sig.reset();

    return message;
}

Tag2::Ptr standalone_signature(const Tag5::Ptr & pri, const Tag2::Ptr & src, const std::string & passphrase, const uint8_t hash){
    Tag2::Ptr sig = create_sig_packet(0x02, pri, nullptr, hash);
    std::string digest = to_sign_02(src);
    sig -> set_left16(digest.substr(0, 2));
    sig -> set_mpi(pka_sign(digest, pri, passphrase, src -> get_hash()));

    return sig;
}

Tag2::Ptr sign_primary_key(const Tag5::Ptr & pri, const ID::Ptr & id, const std::string & passphrase, const uint8_t cert, const uint8_t hash){
    if ((cert < 0x10) || (cert > 0x13)){
        std::stringstream s; s << static_cast <unsigned int> (cert);
        throw std::runtime_error("Error: Invalid Certification Value: " + s.str());
    }

    Tag2::Ptr sig = create_sig_packet(cert, pri, nullptr, hash);
    std::string digest;
    // really not necessary since they all call to_sign_10
    if (cert == 0x10){
        digest = to_sign_10(pri, id, sig);
    }
    else if (cert == 0x11){
        digest = to_sign_11(pri, id, sig);
    }
    else if (cert == 0x12){
        digest = to_sign_12(pri, id, sig);
    }
    else if (cert == 0x13){
        digest = to_sign_13(pri, id, sig);
    }

    sig -> set_left16(digest.substr(0, 2));
    sig -> set_mpi(pka_sign(digest, pri, passphrase, sig -> get_hash()));

    return sig;
}

PGPPublicKey sign_primary_key(const PGPSecretKey & signer, const std::string & passphrase, const PGPPublicKey & signee, const uint8_t cert, const uint8_t hash){
    if (signee.get_ASCII_Armor() != 1){
        throw std::runtime_error("Error: Signee key should be public.");
    }

    if (signer.get_ASCII_Armor() != 2){
        throw std::runtime_error("Error: Signer key should be private.");
    }

    if ((cert < 0x10) || (cert > 0x13)){
        std::stringstream s; s << static_cast <unsigned int> (cert);
        throw std::runtime_error("Error: Invalid Certification Value: " + s.str());
    }

    Tag6::Ptr signee_primary_key = nullptr;
    ID::Ptr signee_id = nullptr;

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

    if (!signee_primary_key){
        throw std::runtime_error("Error: No Signee primary key found.");
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

    if (!signee_id){
        throw std::runtime_error("Error: No Signee user ID found.");
    }

    // move i to after primary key signature
    i++;

    // get signer's signing packet
    Tag5::Ptr signer_signing_key = find_signing_key(signer, 5);

    // check if the signer has alreaady signed this key
    unsigned int j = i;
    while ((j < signee_packets.size()) && (signee_packets[j] -> get_tag() == 2)){
        std::string raw = signee_packets[j++] -> raw();
        Tag2 tag2(raw);
        // search unhashed subpackets first (key id is usually in there)
        for(Subpacket::Ptr const & s : tag2.get_unhashed_subpackets()){
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
        for(Subpacket::Ptr const & s : tag2.get_hashed_subpackets()){
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
    Tag2::Ptr sig = create_sig_packet(cert, signer_signing_key, nullptr, hash);
    std::string digest;
    // really not necessary since they all call to_sign_10
    if (cert == 0x10){
        digest = to_sign_10(signee_primary_key, signee_id, sig);
    }
    else if (cert == 0x11){
        digest = to_sign_11(signee_primary_key, signee_id, sig);
    }
    else if (cert == 0x12){
        digest = to_sign_12(signee_primary_key, signee_id, sig);
    }
    else if (cert == 0x13){
        digest = to_sign_13(signee_primary_key, signee_id, sig);
    }

    sig -> set_left16(digest.substr(0, 2));
    sig -> set_mpi(pka_sign(digest, signer_signing_key, passphrase, sig -> get_hash()));

    // Create output key
    PGPPublicKey out(signee);
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

    signer_signing_key.reset();
    for(Packet::Ptr & p : out_packets){
        p.reset();
    }

    return out;
}

Tag2::Ptr sign_subkey(const Tag5::Ptr & primary, const Tag7::Ptr & sub, const std::string & passphrase, const uint8_t hash){
    Tag2::Ptr sig = create_sig_packet(0x18, primary, nullptr, hash);

    std::string digest = to_sign_18(primary, sub, sig);

    sig -> set_left16(digest.substr(0, 2));
    sig -> set_mpi(pka_sign(digest, primary, passphrase, sig -> get_hash()));

    return sig;
}

Tag2::Ptr sign_primary_key_binding(const Tag7::Ptr & subpri, const std::string & passphrase, const Tag6::Ptr & primary, const Tag14::Ptr & subkey, const uint8_t hash){
    Tag2::Ptr sig = create_sig_packet(0x19, subpri, nullptr, hash);

    std::string digest = to_sign_18(primary, subkey, sig);

    sig -> set_left16(digest.substr(0, 2));
    sig -> set_mpi(pka_sign(digest, subpri, passphrase, sig -> get_hash()));

    return sig;
}

Tag2::Ptr sign_primary_key_binding(const PGPSecretKey & pri, const std::string & passphrase, const PGPPublicKey & signee, const uint8_t hash){
    // find signing subkey
    Key::Ptr subkey = find_signing_key(pri, 7);
    if (!subkey){
        throw std::runtime_error("Error: No Signing Subkey found.");
    }

    // move subkey data into subkey packet
    std::string raw = subkey -> raw();
    subkey.reset();
    Tag7::Ptr signer_subkey(new Tag7(raw));

    // get signee primary and subkey
    Tag6::Ptr signee_primary = nullptr;
    for(Packet::Ptr const & p : pri.get_packets()){
        if (p -> get_tag() == 6){
            std::string raw = p -> raw();
            signee_primary = std::make_shared <Tag6> (raw);
            break;
        }
    }

    if (!signee_primary){
        signer_subkey.reset();
        throw std::runtime_error("Error: Signee Primary Key not found.");
    }

    Tag14::Ptr signee_subkey = nullptr;
    for(Packet::Ptr const & p : pri.get_packets()){
        if (p -> get_tag() == 14){
            std::string raw = p -> raw();
            signee_subkey = std::make_shared <Tag14> (raw);
            break;
        }
    }

    if (!signee_subkey){
        signer_subkey.reset();
        signee_primary.reset();
        throw std::runtime_error("Error: Singee Subkey not found.");
    }

    Tag2::Ptr sig = sign_primary_key_binding(signer_subkey, passphrase, signee_primary, signee_subkey, hash);

    signer_subkey.reset();
    signee_primary.reset();
    signee_subkey.reset();

    return sig;
}

#include "sign.h"

// possible to mess up
User::Ptr find_user_id(const PGPSecretKey & k){
    for(Packet::Ptr const & p : k.get_packets()){
        if ((p -> get_tag() == Packet::ID::User_ID)       ||
            (p -> get_tag() == Packet::ID::User_Attribute)){
            return std::static_pointer_cast <User> (p);
        }
    }
    return nullptr;
}

PKA::Values pka_sign(const std::string & digest, const uint8_t pka, const PKA::Values & pub, const PKA::Values & pri, const uint8_t h){
    if ((pka == PKA::ID::RSA_Encrypt_or_Sign) ||
        (pka == PKA::ID::RSA_Sign_Only)){
        // RFC 4880 sec 5.2.2
        // If RSA, hash value is encoded using EMSA-PKCS1-v1_5
        return {RSA_sign(EMSA_PKCS1_v1_5(h, digest, bitsize(pub[0]) >> 3), pri, pub)};
    }
    else if (pka == PKA::ID::DSA){
        return DSA_sign(digest, pri, pub);
    }
    else{
        throw std::runtime_error("Error: Undefined or incorrect PKA number: " + std::to_string(pka));
    }
    return {};
}

PKA::Values pka_sign(const std::string & digest, const Tag5::Ptr & tag5, const std::string & passphrase, const uint8_t h){
    if (!tag5){
        throw std::runtime_error("Error: No secret key packet provided.");
    }

    PKA::Values pub = tag5 -> get_mpi();
    PKA::Values pri = tag5 -> decrypt_secret_keys(passphrase);
    return pka_sign(digest, tag5 -> get_pka(), pub, pri, h);
}

Tag2::Ptr create_sig_packet(const uint8_t type, const uint8_t pka, const uint8_t hash, const std::string & keyid, const uint8_t version){
    // Set up signature packet
    Tag2::Ptr tag2 = std::make_shared <Tag2> ();
    tag2 -> set_version(version);
    tag2 -> set_pka(pka);
    tag2 -> set_type(type);
    tag2 -> set_hash(hash);

    // Set Time
    Tag2Sub2::Ptr tag2sub2 = std::make_shared <Tag2Sub2> ();
    tag2sub2 -> set_time(now());
    tag2 -> set_hashed_subpackets({tag2sub2});

    // Set Key ID
    Tag2Sub16::Ptr tag2sub16 = std::make_shared <Tag2Sub16> ();
    tag2sub16 -> set_keyid(keyid);
    tag2 -> set_unhashed_subpackets({tag2sub16});

    return tag2;
}

Tag2::Ptr create_sig_packet(const Tag5::Ptr & tag5, const uint8_t type, const uint8_t hash, const uint8_t version){
    if (!tag5){
        throw std::runtime_error("Error: No private key packet.");
    }

    return create_sig_packet(type, tag5 -> get_pka(), hash, tag5 -> get_keyid(), version);
}

Tag2::Ptr create_sig_packet(const PGPSecretKey & pri, const uint8_t type, const uint8_t version){
    Tag5::Ptr tag5 = std::static_pointer_cast <Tag5> (find_signing_key(pri, Packet::ID::Secret_Key));
    if (!tag5){
        throw std::runtime_error("Error: No Private Key packet found.");
    }

    return create_sig_packet(tag5, type, version);
}

PGPDetachedSignature sign_detached_signature(const PGPSecretKey & pri, const std::string & passphrase, const std::string & data, const uint8_t hash){
    PGPDetachedSignature signature;
    signature.set_type(PGP::Type::SIGNATURE);
    signature.set_keys({std::make_pair("Version", "cc")});
    signature.set_packets({sign_binary(pri, passphrase, binary_to_canonical(data), hash)});

    return signature;
}

// 0x00: Signature of a binary document.
Tag2::Ptr sign_binary(const PGPSecretKey & pri, const std::string & passphrase, const std::string & data, const uint8_t version, const uint8_t hash){
    if (pri.get_type() != PGP::Type::PRIVATE_KEY_BLOCK){
        throw std::runtime_error("Error: A private key is required.");
    }

    Tag5::Ptr signer = std::static_pointer_cast <Tag5> (find_signing_key(pri, Packet::ID::Secret_Key));
    if (!signer){
        throw std::runtime_error("Error: No Private Key for signing found.");
    }

    // Check if key has been revoked
    if (check_revoked(pri, signer -> get_keyid())){
        throw std::runtime_error("Error: Key " + hexlify(signer -> get_keyid()) + " has been revoked. Nothing done.");
    }

    // create Signature Packet
    Tag2::Ptr sig = create_sig_packet(Signature_Type::ID::Signature_of_a_binary_document, signer -> get_pka(), hash, signer -> get_keyid(), version);
    std::string digest = to_sign_00(binary_to_canonical(data), sig);
    sig -> set_left16(digest.substr(0, 2));
    sig -> set_mpi(pka_sign(digest, signer, passphrase, sig -> get_hash()));

    return sig;
}

PGPMessage sign_message(const PGPSecretKey & pri, const std::string & passphrase, const std::string & filename, const std::string & data, const uint8_t hash, const uint8_t compress, const uint8_t version){
    // find signing key
    Tag5::Ptr tag5 = std::static_pointer_cast <Tag5> (find_signing_key(pri, Packet::ID::Secret_Key));
    if (!tag5){
        throw std::runtime_error("Error: No signing key found.");
    }

    // find matching signature packet
    Tag2::Ptr keysig = nullptr;
    for(Packet::Ptr const & p : pri.get_packets()){
        if (p -> get_tag() == Packet::ID::Signature){
            Tag2 * temp = new Tag2(p -> raw());
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
    User::Ptr id = find_user_id(pri);
    if (!id){
        throw std::runtime_error("Error: Cannot find Signing Key ID packet.");
    }

    // create One-Pass Signature Packet
    Tag4::Ptr tag4 = std::make_shared <Tag4> ();
    tag4 -> set_type(0);
    tag4 -> set_hash(hash);
    tag4 -> set_pka(tag5 -> get_pka());
    tag4 -> set_keyid(keysig -> get_keyid());
    tag4 -> set_nested(1); // 1 for no nesting

    // put source data into Literal Data Packet
    Tag11::Ptr tag11 = std::make_shared <Tag11> ();
    tag11 -> set_format('b');
    tag11 -> set_filename(filename);
    tag11 -> set_time(now());
    tag11 -> set_literal(data);

    // sign data
    Tag2::Ptr tag2 = create_sig_packet(tag5, Signature_Type::ID::Signature_of_a_binary_document, hash, version);
    std::string digest = to_sign_00(tag11 -> get_literal(), tag2);
    tag2 -> set_left16(digest.substr(0, 2));
    tag2 -> set_mpi(pka_sign(digest, tag5, passphrase, hash));

    // put everything together
    PGPMessage signature;
    signature.set_type(PGP::Type::SIGNATURE);
    signature.set_keys({std::make_pair("Version", "cc")});
    signature.set_packets({tag4, tag11, tag2});

    if (compress){ // only use a Compressed Data Packet if compression was used; don't bother for uncompressed data
        Tag8 tag8;
        tag8.set_data(signature.raw());
        tag8.set_comp(compress);
        std::string raw = tag8.write(2);
        signature = PGPMessage(raw);
    }

    return signature;
}

// 0x01: Signature of a canonical text document.
PGPCleartextSignature sign_cleartext(const PGPSecretKey & pri, const std::string & passphrase, const std::string & text, const uint8_t hash, const uint8_t version){
    if (pri.get_type() != PGP::Type::PRIVATE_KEY_BLOCK){
        throw std::runtime_error("Error: A private key is required.");
    }

    Tag5::Ptr signer = std::static_pointer_cast <Tag5> (find_signing_key(pri, Packet::ID::Secret_Key));
    if (!signer){
        throw std::runtime_error("Error: No Private Key packet found.");
    }

    // create signature
    Tag2::Ptr sig = create_sig_packet(signer, Signature_Type::ID::Signature_of_a_canonical_text_document, hash, version);
    const std::string digest = to_sign_01(PGPCleartextSignature::data_to_text(text), sig);
    sig -> set_left16(digest.substr(0, 2));
    sig -> set_mpi(pka_sign(digest, signer, passphrase, hash));

    // put signature into Detached Signature
    PGPDetachedSignature signature;
    signature.set_type(PGP::Type::SIGNATURE);
    signature.set_keys({std::make_pair("Version", "cc")});
    signature.set_packets({sig});

    // put signature under cleartext
    PGPCleartextSignature message;
    message.set_hash_armor_header({std::make_pair("Hash", Hash::Name.at(hash))});
    message.set_message(text);
    message.set_sig(signature);

    return message;
}

// 0x02: Standalone signature.
Tag2::Ptr standalone_signature(const Tag5::Ptr & pri, const Tag2::Ptr & src, const std::string & passphrase, const uint8_t hash, const uint8_t version){
    Tag2::Ptr sig = create_sig_packet(pri, Signature_Type::ID::Standalone_signature, hash, version);
    std::string digest = to_sign_02(src);
    sig -> set_left16(digest.substr(0, 2));
    sig -> set_mpi(pka_sign(digest, pri, passphrase, src -> get_hash()));

    return sig;
}

// 0x10: Generic certification of a User ID and Public-Key packet.
// 0x11: Persona certification of a User ID and Public-Key packet.
// 0x12: Casual certification of a User ID and Public-Key packet.
// 0x13: Positive certification of a User ID and Public-Key packet.
// mainly used for key generation
Tag2::Ptr sign_primary_key(const Tag5::Ptr & pri, const User::Ptr & id, const std::string & passphrase, const uint8_t cert, const uint8_t hash, const uint8_t version){
    if (!Signature_Type::is_certification(cert)){
        throw std::runtime_error("Error: Invalid Certification Value: " + std::to_string(cert));
    }

    Tag2::Ptr sig = create_sig_packet(pri, cert, hash, version);
    std::string digest;
    // really not necessary since they all call to_sign_10
    if (cert == Signature_Type::ID::Generic_certification_of_a_User_ID_and_Public_Key_packet){
        digest = to_sign_10(pri, id, sig);
    }
    else if (cert == Signature_Type::ID::Persona_certification_of_a_User_ID_and_Public_Key_packet){
        digest = to_sign_11(pri, id, sig);
    }
    else if (cert == Signature_Type::ID::Casual_certification_of_a_User_ID_and_Public_Key_packet){
        digest = to_sign_12(pri, id, sig);
    }
    else if (cert == Signature_Type::ID::Positive_certification_of_a_User_ID_and_Public_Key_packet){
        digest = to_sign_13(pri, id, sig);
    }

    sig -> set_left16(digest.substr(0, 2));
    sig -> set_mpi(pka_sign(digest, pri, passphrase, sig -> get_hash()));

    return sig;
}

PGPPublicKey sign_primary_key(const PGPSecretKey & signer, const std::string & passphrase, const PGPPublicKey & signee, const uint8_t cert, const uint8_t hash, const uint8_t version){
    if (signee.get_type() != PGP::Type::PUBLIC_KEY_BLOCK){
        throw std::runtime_error("Error: Signee key should be public.");
    }

    if (signer.get_type() != PGP::Type::PRIVATE_KEY_BLOCK){
        throw std::runtime_error("Error: Signer key should be private.");
    }

    if (!Signature_Type::is_certification(cert)){
        throw std::runtime_error("Error: Invalid Certification Value: " + std::to_string(cert));
    }

    Key::Ptr signee_primary_key = nullptr;
    User::Ptr signee_id = nullptr;

    // find primary key; generally packet[0]
    PGP::Packets signee_packets = signee.get_packets_clone();
    unsigned int i = 0;
    for(i = 0; i < signee_packets.size(); i++){
        if (signee_packets[i] -> get_tag() == Packet::ID::Public_Key){
            signee_primary_key = std::make_shared <Key> (signee_packets[i] -> raw());
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
    if ((signee_packets[i] -> get_tag() != Packet::ID::User_ID) &&
        (signee_packets[i] -> get_tag() != Packet::ID::User_Attribute)){
        throw std::runtime_error("Error: No User ID packet following Primary Key");
    }

    // get signee user id packet
    std::string raw_id = signee_packets[i] -> raw();
    if (signee_packets[i] -> get_tag() == Packet::ID::User_ID){
        signee_id = std::make_shared <Tag13> (raw_id);
    }
    else if (signee_packets[i] -> get_tag() == Packet::ID::User_Attribute){
        signee_id = std::make_shared <Tag17> (raw_id);
    }

    if (!signee_id){
        throw std::runtime_error("Error: No Signee user ID found.");
    }

    // move i to after primary key signature
    i++;

    // get signer's signing packet
    Tag5::Ptr signer_signing_key = std::static_pointer_cast <Tag5> (find_signing_key(signer, Packet::ID::Secret_Key));

    // check if the signer has alreaady signed this key
    unsigned int j = i;
    while ((j < signee_packets.size()) && (signee_packets[j] -> get_tag() == Packet::ID::Signature)){
        std::string raw = signee_packets[j++] -> raw();
        Tag2 tag2(raw);
        // search unhashed subpackets first (key id is usually in there)
        for(Tag2Subpacket::Ptr const & s : tag2.get_unhashed_subpackets()){
            if (s -> get_type() == Tag2Subpacket::ID::Issuer){
                if (Tag2Sub16(s -> raw()).get_keyid() == signer_signing_key -> get_keyid()){
                    std::cerr << "Warning: Key " << signee << " has already been signed by this key " << signer << ". Nothing done. " << std::endl;
                    return signee;
                }
            }
        }

        // search hashed subpackets
        for(Tag2Subpacket::Ptr const & s : tag2.get_hashed_subpackets()){
            if (s -> get_type() == Tag2Subpacket::ID::Issuer){
                if (Tag2Sub16(s -> raw()).get_keyid() == signer_signing_key -> get_keyid()){
                    std::cerr << "Warning: Key " << signee << " has already been signed by this key " << signer << std::endl;
                    return signee;
                }
            }
        }
    }

    // sign key
    Tag2::Ptr sig = create_sig_packet(signer_signing_key, cert, hash, version);
    std::string digest;
    // really not necessary since they all call to_sign_10
    if (cert == Signature_Type::ID::Generic_certification_of_a_User_ID_and_Public_Key_packet){
        digest = to_sign_10(signee_primary_key, signee_id, sig);
    }
    else if (cert == Signature_Type::ID::Persona_certification_of_a_User_ID_and_Public_Key_packet){
        digest = to_sign_11(signee_primary_key, signee_id, sig);
    }
    else if (cert == Signature_Type::ID::Casual_certification_of_a_User_ID_and_Public_Key_packet){
        digest = to_sign_12(signee_primary_key, signee_id, sig);
    }
    else if (cert == Signature_Type::ID::Positive_certification_of_a_User_ID_and_Public_Key_packet){
        digest = to_sign_13(signee_primary_key, signee_id, sig);
    }

    sig -> set_left16(digest.substr(0, 2));
    sig -> set_mpi(pka_sign(digest, signer_signing_key, passphrase, sig -> get_hash()));

    // Create output key
    PGPPublicKey out(signee);
    PGP::Packets out_packets;

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

// 0x18: Subkey Binding Signature
// mainly used for key generation
Tag2::Ptr sign_subkey(const Tag5::Ptr & primary, const Tag7::Ptr & sub, const std::string & passphrase, const uint8_t hash, const uint8_t version){
    Tag2::Ptr sig = create_sig_packet(primary, Signature_Type::ID::Subkey_Binding_Signature, hash, version);

    std::string digest = to_sign_18(primary, sub, sig);

    sig -> set_left16(digest.substr(0, 2));
    sig -> set_mpi(pka_sign(digest, primary, passphrase, sig -> get_hash()));

    return sig;
}

// 0x19: Primary Key Binding Signature
Tag2::Ptr sign_primary_key_binding(const Tag7::Ptr & subpri, const std::string & passphrase, const Tag6::Ptr & primary, const Tag14::Ptr & subkey, const uint8_t hash, const uint8_t version){
    Tag2::Ptr sig = create_sig_packet(subpri, Signature_Type::ID::Primary_Key_Binding_Signature, hash, version);

    std::string digest = to_sign_18(primary, subkey, sig);

    sig -> set_left16(digest.substr(0, 2));
    sig -> set_mpi(pka_sign(digest, subpri, passphrase, sig -> get_hash()));

    return sig;
}

Tag2::Ptr sign_primary_key_binding(const PGPSecretKey & pri, const std::string & passphrase, const PGPPublicKey & signee, const uint8_t hash, const uint8_t version){
    // find signing subkey
    Key::Ptr subkey = find_signing_key(pri, Packet::ID::Secret_Subkey);
    if (!subkey){
        throw std::runtime_error("Error: No Signing Subkey found.");
    }

    // move subkey data into subkey packet
    Tag7::Ptr signer_subkey = std::make_shared <Tag7> (subkey -> raw());

    // get signee primary and subkey
    Tag6::Ptr signee_primary = nullptr;
    for(Packet::Ptr const & p : pri.get_packets()){
        if (p -> get_tag() == Packet::ID::Public_Key){
            signee_primary = std::make_shared <Tag6> (p -> raw());
            break;
        }
    }

    if (!signee_primary){
        throw std::runtime_error("Error: Signee Primary Key not found.");
    }

    Tag14::Ptr signee_subkey = nullptr;
    for(Packet::Ptr const & p : pri.get_packets()){
        if (p -> get_tag() == Packet::ID::Public_Subkey){
            signee_subkey = std::make_shared <Tag14> (p -> raw());
            break;
        }
    }

    if (!signee_subkey){
        throw std::runtime_error("Error: Singee Subkey not found.");
    }

    return sign_primary_key_binding(signer_subkey, passphrase, signee_primary, signee_subkey, hash, version);
}

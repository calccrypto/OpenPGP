#include "revoke.h"

bool check_revoked(const PGP::Packets & packets, const std::string & keyid){
    for(Packet::Ptr const & p: packets){
        // if a signature packet
        if (p -> get_tag() == Packet::SIGNATURE){
            Tag2::Ptr tag2 = std::static_pointer_cast <Tag2> (p);
            // if the signature packet is a key/subkey revocation signature
            if ((tag2 -> get_type() == Signature_Type::KEY_REVOCATION_SIGNATURE)   ||
                (tag2 -> get_type() == Signature_Type::SUBKEY_REVOCATION_SIGNATURE)){
                // and the keyid matches the one being searched
                if (tag2 -> get_keyid() == keyid){
                    return true;
                }
            }
        }
    }
    return false;
}

bool check_revoked(const PGPKey & key, const std::string & keyid){
    return check_revoked(key.get_packets(), keyid);
}

// 0x20: Key revocation signature
// main function to revoke a primary key
Tag2::Ptr revoke_primary_key_cert(PGPSecretKey & pri, const std::string & passphrase, const uint8_t code, const std::string & reason, const uint8_t version){
    if (pri.get_type() != PGP::PRIVATE_KEY_BLOCK){
        throw std::runtime_error("Error: A private key is required for the first argument.");
    }

    Tag5::Ptr signer = find_signing_key(pri);
    if (!signer){
        throw std::runtime_error("Error: No Secret Key packet found.");
    }

    Tag2::Ptr sig = create_sig_packet(version, Signature_Type::KEY_REVOCATION_SIGNATURE, signer -> get_pka(), Hash::SHA1, signer -> get_keyid());

    // add revocation subpacket
    std::vector <Tag2Subpacket::Ptr> hashed_subpackets = sig -> get_hashed_subpackets_clone();
    Tag2Sub29::Ptr revoke = std::make_shared <Tag2Sub29> ();
    revoke -> set_code(code);
    revoke -> set_reason(reason);
    hashed_subpackets.push_back(revoke);
    sig -> set_hashed_subpackets(hashed_subpackets);

    // set signature data
    std::string digest = to_sign_20(signer, sig);
    sig -> set_left16(digest.substr(0, 2));
    PKA::Values vals = pka_sign(digest, signer -> get_pka(), signer -> get_mpi(), signer -> decrypt_secret_keys(passphrase), sig -> get_hash());
    if (!vals.size()){
        // error += "Error: PKA Signing failed.\n";
        return nullptr;
    }
    sig -> set_mpi(vals);

    return sig;
}

PGPPublicKey revoke_primary_key_cert_key(PGPSecretKey & pri, const std::string & passphrase, const uint8_t code, const std::string & reason, const uint8_t version){
    Tag2::Ptr sig = revoke_primary_key_cert(pri, passphrase, code, reason);

    PGPPublicKey signature;
    signature.set_type(PGP::PUBLIC_KEY_BLOCK);
    signature.set_keys({std::make_pair("Version", "cc"), std::make_pair("Comment", "Revocation Certificate")});
    signature.set_packets({sig});

    return signature;
}

// 0x28: Subkey revocation signature
// main function to revoke a subkey
Tag2::Ptr revoke_subkey_cert(PGPSecretKey & pri, const std::string & passphrase, const uint8_t code, const std::string & reason, const uint8_t version){
    if (pri.get_type() != PGP::PRIVATE_KEY_BLOCK){
        throw std::runtime_error("Error: A private key is required for the first argument.");
    }

    Tag5::Ptr signer = find_signing_key(pri);
    if (!signer){
        throw std::runtime_error("Error: Private signing key not found");
    }

    // find subkey
    Tag7::Ptr key = nullptr;
    PGP::Packets packets = pri.get_packets();
    for(Packet::Ptr const & p : packets){
        if (p -> get_tag() == Packet::SECRET_SUBKEY){
            key = std::static_pointer_cast <Tag7> (p);
            break;
        }
    }

    if (!key){
        throw std::runtime_error("Error: No Secret Subkey packet found.");
    }

    Tag2::Ptr sig = create_sig_packet(version, Signature_Type::SUBKEY_REVOCATION_SIGNATURE, signer -> get_pka(), Hash::SHA1, signer -> get_keyid());

    // add revocation subpacket
    std::vector <Tag2Subpacket::Ptr> hashed_subpackets = sig -> get_hashed_subpackets_clone();
    Tag2Sub29::Ptr revoke = std::make_shared <Tag2Sub29> ();
    revoke -> set_code(code);
    revoke -> set_reason(reason);
    hashed_subpackets.push_back(revoke);
    sig -> set_hashed_subpackets(hashed_subpackets);

    // set signature data
    std::string digest = to_sign_28(key, sig);
    sig -> set_left16(digest.substr(0, 2));
    PKA::Values vals = pka_sign(digest, signer -> get_pka(), signer -> get_mpi(), signer -> decrypt_secret_keys(passphrase), sig -> get_hash());
    if (!vals.size()){
        // error += "Error: PKA Signing failed.\n";
        return nullptr;
    }
    sig -> set_mpi(vals);

    return sig;
}

PGPPublicKey revoke_subkey_cert_key(PGPSecretKey & pri, const std::string & passphrase, const uint8_t code, const std::string & reason, const uint8_t version){
    Tag2::Ptr sig = revoke_subkey_cert(pri, passphrase, code, reason);

    PGPPublicKey signature;
    signature.set_type(PGP::PUBLIC_KEY_BLOCK);
    signature.set_keys({std::make_pair("Version", "cc"), std::make_pair("Comment", "Revocation Certificate")});
    signature.set_packets({sig});

    return signature;
}

// 0x30: Certification revocation signature
PGPPublicKey revoke_uid(PGPPublicKey & pub, PGPSecretKey & pri, const std::string passphrase, const uint8_t code, const std::string & reason, const uint8_t version){
    if (pub.get_type() != PGP::PUBLIC_KEY_BLOCK){
        throw std::runtime_error("Error: A public key is required for the first argument.");
    }
    if (pri.get_type() != PGP::PRIVATE_KEY_BLOCK){
        throw std::runtime_error("Error: A private key is required for the second argument.");
    }

    Tag5::Ptr signer = find_signing_key(pri);
    if (!signer){
        throw std::runtime_error("Error: Private signing key not found");
    }

    // find subkey
    Tag7::Ptr key = nullptr;
    PGP::Packets packets = pri.get_packets();
    for(Packet::Ptr const & p : packets){
        if (p -> get_tag() == 7){
            key = std::static_pointer_cast <Tag7> (p);
            break;
        }
    }

    if (!key){
        throw std::runtime_error("Error: No Secret Subkey packet found.");
    }

    User::Ptr uid = nullptr;
    for(Packet::Ptr const & p : pri.get_packets()){
        if ((p -> get_tag() == Packet::USER_ID)       ||
            (p -> get_tag() == Packet::USER_ATTRIBUTE)){
            uid = std::static_pointer_cast <User> (p);
        }
    }

    if (!uid){
        throw std::runtime_error("Error: No User ID packet found.");
    }

    Tag2::Ptr sig = create_sig_packet(version, Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE, signer -> get_pka(), Hash::SHA1, signer -> get_keyid());

    // add revocation subpacket
    std::vector <Tag2Subpacket::Ptr> hashed_subpackets = sig -> get_hashed_subpackets_clone();
    Tag2Sub29::Ptr revoke = std::make_shared <Tag2Sub29> ();
    revoke -> set_code(code);
    revoke -> set_reason(reason);
    hashed_subpackets.push_back(revoke);
    sig -> set_hashed_subpackets(hashed_subpackets);

    // set signature data
    std::string digest = to_sign_30(key, uid, sig);
    sig -> set_left16(digest.substr(0, 2));
    PKA::Values vals = pka_sign(digest, signer -> get_pka(), signer -> get_mpi(), signer -> decrypt_secret_keys(passphrase), sig -> get_hash());
    if (!vals.size()){
        // error += "Error: PKA Signing failed.\n";
        return PGPPublicKey();
    }
    sig -> set_mpi(vals);

    // Create output key
    PGPPublicKey revoked(pub);
    PGP::Packets old_packets = pub.get_packets_clone();
    PGP::Packets new_packets;

    // push all packets up to and including revoked packet into new packets
    unsigned int i = 0;
    do{
        new_packets.push_back(old_packets[i]);
    }
    while ((i < old_packets.size()) && (old_packets[i++] -> get_tag() != Packet::USER_ID));

    // append revocation signature to key
    new_packets.push_back(sig);

    // append rest of packets
    while (i < old_packets.size()){
        new_packets.push_back(old_packets[i++]);
    }
    revoked.set_packets(new_packets);

    return revoked;
}

PGPPublicKey revoke_key(PGPSecretKey & pri, const std::string & passphrase, const uint8_t code, const std::string & reason, const uint8_t version){
    if (pri.get_type() != PGP::PRIVATE_KEY_BLOCK){
        throw std::runtime_error("Error: A private key is required for the second argument.");
    }

    PGP::Packets packets = pri.get_packets();

    Tag2::Ptr rev = revoke_primary_key_cert(pri, passphrase, code, reason);
    Tag6::Ptr primary = std::static_pointer_cast <Tag6> (packets[0]);

    // assume first packet is primary key, and add a revocation signature as the next packet
    PGP::Packets new_packets = {primary, rev};

    // clone the rest of the packets
    for(unsigned int i = 1; i < packets.size(); i++){
        new_packets.push_back(packets[i] -> clone());
    }

    PGPPublicKey revoked;
    revoked.set_type(PGP::PUBLIC_KEY_BLOCK);
    revoked.set_keys(pri.get_keys());
    revoked.set_packets(new_packets);

    return revoked;
}

PGPPublicKey revoke_subkey(PGPSecretKey & pri, const std::string & passphrase, const uint8_t code, const std::string & reason, const uint8_t version){
    if (pri.get_type() != PGP::PRIVATE_KEY_BLOCK){
        throw std::runtime_error("Error: A private key is required for the second argument.");
    }

    PGP::Packets packets = pri.get_packets();

    Tag2::Ptr rev = revoke_subkey_cert(pri, passphrase, code, reason);

    // assume first packet is primary key
    PGP::Packets new_packets;

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
    revoked.set_type(PGP::PUBLIC_KEY_BLOCK);
    revoked.set_keys(pri.get_keys());
    revoked.set_packets(new_packets);

    return revoked;
}

PGPPublicKey revoke_with_cert(const PGPKey & key, PGPPublicKey & revoke, const uint8_t version){
    if (key.get_type() != PGP::PUBLIC_KEY_BLOCK){
        throw std::runtime_error("Error: A public key is required.");
    }

    if (revoke.get_type() != PGP::PUBLIC_KEY_BLOCK){
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

    Tag2::Ptr tag2 = std::static_pointer_cast <Tag2> (revoke.get_packets()[0]);

    if ((tag2 -> get_type() != Signature_Type::KEY_REVOCATION_SIGNATURE) &&
        (tag2 -> get_type() != Signature_Type::SUBKEY_REVOCATION_SIGNATURE)){
        throw std::runtime_error("Error: Invalid signature type found: " + std::to_string(tag2 -> get_type()));
    }

    // which packet to look for
    uint8_t which = (tag2 -> get_type() == Signature_Type::KEY_REVOCATION_SIGNATURE)?Packet::PUBLIC_KEY:Packet::PUBLIC_SUBKEY;

    std::string r_keyid = tag2 -> get_keyid();
    std::string k_keyid = "";

    if (!r_keyid.size()){
        throw std::runtime_error("Error: No key id found.");
    }

    // find key with key id
    for(Packet::Ptr const & p: key.get_packets()){
        if (p -> get_tag() == which){
            k_keyid = std::static_pointer_cast <Tag6> (p) -> get_keyid();
            break;
        }
    }

    if (r_keyid != k_keyid){
        throw std::runtime_error("Error: Revocation Certificate does not revoke this Public Key.");
    }

    if (!verify_revoke(key, revoke)){
        throw std::runtime_error("Error: This revocation certificate was not signed by this key.");
    }

    // Create output key
    PGPPublicKey revoked(key);
    PGP::Packets old_packets = key.get_packets_clone();
    PGP::Packets new_packets;

    // push all packets up to and including revoked packet into new packets
    unsigned int i = 0;
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

    return revoked;
}

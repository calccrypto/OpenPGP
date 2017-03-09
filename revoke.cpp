#include "revoke.h"

int check_revoked(const PGPKey & key, std::string & error){
    if (!key.meaningful(error)){
        error += "Error: Bad Key.\n";
        return -1;
    }

    // Key::Ptr signing_key = find_signing_key(key);

    const PGP::Packets packets = key.get_packets();
    if (packets[1] -> get_tag() == Packet::SIGNATURE){
        Tag2::Ptr tag2 = std::static_pointer_cast <Tag2> (packets[1]);
        // if the signature packet is a key/subkey revocation signature
        if (tag2 -> get_type() == Signature_Type::KEY_REVOCATION_SIGNATURE){
            // TODO verify the signature/hash bits
            return true;
        }

        error += "Error: Bad signature type.\n";
        return -1;
    }

    for(Packet::Ptr const & p: key.get_packets()){
        // if a signature packet
        if (p -> get_tag() == Packet::SIGNATURE){
            Tag2::Ptr tag2 = std::static_pointer_cast <Tag2> (p);
            // if the signature packet is a key/subkey revocation signature
            if (tag2 -> get_type() == Signature_Type::SUBKEY_REVOCATION_SIGNATURE){
                // TODO verify the signature/hash bits
                return true;
            }
            else{
                error += "Error: Bad signature type.\n";
                return -1;
            }
        }
    }

    return false;
}

int check_revoked(const PGPKey & key){
    std::string error;
    return check_revoked(key, error);
}

// Returns revocation signature packet
Tag2::Ptr revoke_key_sig(const RevArgs & args, const uint8_t type, std::string & error){
    if (!args.valid(error)){
        error += "Error: Bad arguments.\n";
        return nullptr;
    }

    // only allow key and subkey revocation here
    if ((type != Signature_Type::KEY_REVOCATION_SIGNATURE)   &&
        (type != Signature_Type::SUBKEY_REVOCATION_SIGNATURE)){
        error += "Error: Bad revocation type.\n";
        return nullptr;
    }

    Tag5::Ptr signer = std::static_pointer_cast <Tag5> (find_signing_key(args.pri));
    if (!signer){
        error += "Error: No Secret Key packet found.\n";
        return nullptr;
    }

    Tag2::Ptr sig = create_sig_packet(args.version, type, signer -> get_pka(), args.hash, signer -> get_keyid());

    // add revocation subpacket
    std::vector <Tag2Subpacket::Ptr> hashed_subpackets = sig -> get_hashed_subpackets_clone();
    Tag2Sub29::Ptr revoke = std::make_shared <Tag2Sub29> ();
    revoke -> set_code(args.code);
    revoke -> set_reason(args.reason);
    hashed_subpackets.push_back(revoke);
    sig -> set_hashed_subpackets(hashed_subpackets);

    // set signature data
    std::string digest;
    if (type == Signature_Type::KEY_REVOCATION_SIGNATURE){
        digest = to_sign_20(signer, sig);
    }
    else if (type == Signature_Type::KEY_REVOCATION_SIGNATURE){
        digest = to_sign_20(signer, sig);
    }
    sig -> set_left16(digest.substr(0, 2));
    PKA::Values vals = pka_sign(digest, signer -> get_pka(), signer -> get_mpi(), signer -> decrypt_secret_keys(args.passphrase), sig -> get_hash());
    if (!vals.size()){
        error += "Error: PKA Signing failed.\n";
        return nullptr;
    }
    sig -> set_mpi(vals);

    return sig;
}

Tag2::Ptr revoke_uid_sig(const RevArgs & args, const std::string & ID, std::string & error){
    if (!args.valid(error)){
        error += "Error: Bad arguments.\n";
        return nullptr;
    }


    const Tag5::Ptr signer = std::static_pointer_cast <Tag5> (find_signing_key(args.pri));
    if (!signer){
        error += "Error: Private signing key not found.\n";
        return nullptr;
    }

    // find user information
    User::Ptr user = nullptr;
    for(Packet::Ptr const & p : args.pri.get_packets()){
        if (p -> get_tag() == Packet::USER_ID){
            Tag13::Ptr tag13 = std::static_pointer_cast <Tag13> (p);

            // make sure some part of the User ID matches the requested ID
            if (tag13 -> get_contents().find(ID) != std::string::npos){
                user = tag13;
                break;
            }

            user = nullptr;
        }
        // else if (p -> get_tag() == Packet::USER_ATTRIBUTE){}
    }

    if (!user){
        error += "Error: No user information matching \"" + ID + "\" found.\n";
        return nullptr;
    }

    Tag2::Ptr sig = create_sig_packet(args.version, Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE, signer -> get_pka(), args.hash, signer -> get_keyid());

    // add revocation subpacket
    std::vector <Tag2Subpacket::Ptr> hashed_subpackets = sig -> get_hashed_subpackets_clone();
    Tag2Sub29::Ptr revoke = std::make_shared <Tag2Sub29> ();
    revoke -> set_code(args.code);
    revoke -> set_reason(args.reason);
    hashed_subpackets.push_back(revoke);
    sig -> set_hashed_subpackets(hashed_subpackets);

    // set signature data
    std::string digest = to_sign_30(signer, user, sig);
    sig -> set_left16(digest.substr(0, 2));
    PKA::Values vals = pka_sign(digest, signer -> get_pka(), signer -> get_mpi(), signer -> decrypt_secret_keys(args.passphrase), sig -> get_hash());
    if (!vals.size()){
        error += "Error: PKA Signing failed.\n";
        return nullptr;
    }
    sig -> set_mpi(vals);

    return sig;
}

// creates revocation certificate to be used later
PGPRevocationCertificate revoke_key_cert(const RevArgs & args, const uint8_t type, std::string & error){
    Tag2::Ptr sig = revoke_key_sig(args, type, error);
    if (!sig){
        error += "Error: Could not generate revocation signature packet.\n";
        return PGPRevocationCertificate();
    }

    PGPRevocationCertificate signature;
    signature.set_keys({std::make_pair("Version", "cc"), std::make_pair("Comment", "Revocation Certificate")});
    signature.set_packets({sig});

    return signature;
}

PGPRevocationCertificate revoke_uid_cert(const RevArgs & args, const std::string & ID, std::string & error){
    Tag2::Ptr sig = revoke_uid_sig(args, ID, error);
    if (!sig){
        error += "Error: Could not generate revocation signature packet.\n";
        return PGPRevocationCertificate();
    }

    PGPRevocationCertificate signature;
    signature.set_keys({std::make_pair("Version", "cc"), std::make_pair("Comment", "Revocation Certificate")});
    signature.set_packets({sig});

    return signature;
}

// Directly Revoke (does not write to key; instead, returns new copy of public key)
PGPPublicKey revoke_key(const RevArgs & args, const uint8_t type, std::string & error){
    if (!args.valid(error)){
        error += "Error: Bad key.\n";
        return PGPPublicKey();
    }

    Tag2::Ptr revoke_sig = revoke_key_sig(args, type, error);
    if (!revoke_sig){
        error += "Error: Could not revoke primary key.\n";
        return PGPPublicKey();
    }

    const std::string keyid = args.pri.keyid();

    // make sure that the revocation certificate is for the given key
    if (keyid != revoke_sig -> get_keyid()){
        error += "Error: Revocation certificate is not for key " + hexlify(args.pri.keyid()) + "\n";
        return PGPPublicKey();
    }

    // Create output key
    const PGP::Packets & old_packets = args.pri.get_packets();
    PGP::Packets new_packets = {std::static_pointer_cast <Tag5> (old_packets[0]) -> get_public_ptr()};

    // if the revocation was for the primary key, put it behind the key packet
    if (revoke_sig -> get_type() == Signature_Type::KEY_REVOCATION_SIGNATURE){
        new_packets.push_back(revoke_sig -> clone());
    }

    // push all packets up to the subkey
    unsigned int i = 1;
    while ((i < old_packets.size()) && !Packet::is_subkey(old_packets[i] -> get_tag())){
        new_packets.push_back(old_packets[i++] -> clone());
    }

    // process the subkey key (assume there is only 1)
    new_packets.push_back(std::static_pointer_cast <Tag7> (old_packets[i++]) -> get_public_ptr());

    // if the revocation was for the subkey, find the signature packet for the subkey and put the revocation signature after it
    if (revoke_sig -> get_type() == Signature_Type::SUBKEY_REVOCATION_SIGNATURE){
        #ifndef GPG_COMPATIBLE
        // clone following signature packet
        new_packets.push_back(old_packets[i++] -> clone());
        #endif

        // push revocation packet in
        new_packets.push_back(revoke_sig -> clone());
    }

    // append rest of packets
    while (i < old_packets.size()){
        new_packets.push_back(old_packets[i++] -> clone());
    }

    PGPPublicKey revoked;
    revoked.set_keys(args.pri.get_keys());
    revoked.set_packets(new_packets);

    return revoked;
}

PGPPublicKey revoke_uid(const RevArgs & args, const std::string & ID, std::string & error){
    if (!args.valid(error)){
        error += "Error: Bad arguments.\n";
        return PGPPublicKey();
    }

    PGPRevocationCertificate revoke_cert = revoke_uid_cert(args, ID, error);
    if (!revoke_cert.meaningful(error)){
        error += "Error: Could not revoke certification.\n";
        return PGPPublicKey();
    }

    // make sure that the revocation certificate is for the given key
    const int rc = verify_revoke(args.pri, revoke_cert, error);
    if (rc == 0){
        error += "Error: Revocation certificate is not for key " + hexlify(args.pri.keyid()) + "\n";
        return PGPPublicKey();
    }
    else if (rc == -1){
        error += "Error: verify_revoke failure.\n";
        return PGPPublicKey();
    }

    const PGP::Packets & old_packets = args.pri.get_packets();

    // find user packet position
    PGP::Packets::size_type user_pos;
    for(user_pos = 1; user_pos < old_packets.size(); user_pos++){
        if (old_packets[user_pos] -> get_tag() == Packet::USER_ID){
            // make sure some part of the User ID matches the requested ID
            if (std::static_pointer_cast <Tag13> (old_packets[user_pos]) -> get_contents().find(ID) != std::string::npos){
                break;
            }
        }
        // else if (p -> get_tag() == Packet::USER_ATTRIBUTE){}
    }

    // convert and clone the primary secret key to a primary public key
    PGP::Packets new_packets = {std::static_pointer_cast <Tag5> (old_packets[0]) -> get_public_ptr()};

    // clone all packets up to and including the user packet
    unsigned int i = 1;
    while ((i <= user_pos)){
        new_packets.push_back(old_packets[i++] -> clone());
    }

    // place revocation signature right after the user packet
    new_packets.push_back(std::static_pointer_cast <Tag2> (revoke_cert.get_packets()[0]) -> clone());

    // clone all packets up to the subkey
    while ((i < old_packets.size()) && (old_packets[i] -> get_tag() != Packet::SECRET_SUBKEY)){
        new_packets.push_back(old_packets[i++] -> clone());
    }

    // convert the secret subkey into a public subkey
    new_packets.push_back(std::static_pointer_cast <Tag7> (old_packets[i++]) -> get_public_ptr());

    // clone the rest of the key
    while (i < old_packets.size()){
        new_packets.push_back(old_packets[i++] -> clone());
    }

    PGPPublicKey revoked;
    revoked.set_keys(args.pri.get_keys());
    revoked.set_packets(new_packets);

    return revoked;
}

PGPPublicKey revoke_key_with_cert(const PGPKey & key, const PGPRevocationCertificate & revoke, std::string & error){
    if (!key.meaningful(error)){
        error += "Error: Bad key.\n";
        return PGPPublicKey();
    }

    if (!revoke.meaningful(error)){
        error += "Error: Bad revocation certificate.\n";
        return PGPPublicKey();
    }

    // make sure that the revocation certificate is for the given key
    const int rc = verify_revoke(key, revoke, error);
    if (rc == 0){
        error += "Error: Revocation certificate is not for key " + hexlify(key.keyid()) + "\n";
        return PGPPublicKey();
    }
    else if (rc == -1){
        error += "Error: verify_revoke failure.\n";
        return PGPPublicKey();
    }

    // extract revocation signature; don't need to check - should have been caught by revoke.meaningful()
    Tag2::Ptr revoke_sig = std::static_pointer_cast <Tag2> (revoke.get_packets()[0]);

    const std::string keyid = revoke_sig -> get_keyid();

    // Create output key
    const PGP::Packets & old_packets = key.get_packets();
    PGP::Packets new_packets;

    // process the primary key
    if (old_packets[0] -> get_tag() == Packet::PUBLIC_KEY){
        new_packets.push_back(old_packets[0] -> clone());
    }
    else if (old_packets[0] -> get_tag() == Packet::SECRET_KEY){
        new_packets.push_back(std::static_pointer_cast <Tag5> (old_packets[0]) -> get_public_ptr());
    }

    // if the revocation was for the primary key, put it behind the key packet
    if (revoke_sig -> get_type() == Signature_Type::KEY_REVOCATION_SIGNATURE){
        new_packets.push_back(revoke_sig -> clone());
    }

    // push all packets up to the subkey
    unsigned int i = 1;
    while ((i < old_packets.size()) && !Packet::is_subkey(old_packets[i] -> get_tag())){
        new_packets.push_back(old_packets[i++] -> clone());
    }

    // process the primary key
    if (old_packets[i] -> get_tag() == Packet::PUBLIC_SUBKEY){
        new_packets.push_back(old_packets[i] -> clone());
    }
    else if (old_packets[i] -> get_tag() == Packet::SECRET_SUBKEY){
        new_packets.push_back(std::static_pointer_cast <Tag7> (old_packets[i]) -> get_public_ptr());
    }

    i++;

    // if the revocation was for the subkey, find the signing packet and put the revocation signature after it
    if (revoke_sig -> get_type() == Signature_Type::SUBKEY_REVOCATION_SIGNATURE){
        #ifndef GPG_COMPATIBLE
        // clone following signature packet
        new_packets.push_back(old_packets[i++] -> clone());
        #endif

        // push revocation packet in
        new_packets.push_back(revoke_sig -> clone());
    }

    // append rest of packets
    while (i < old_packets.size()){
        new_packets.push_back(old_packets[i++] -> clone());
    }

    PGPPublicKey revoked;
    revoked.set_keys(key.get_keys());
    revoked.set_packets(new_packets);

    return revoked;
}

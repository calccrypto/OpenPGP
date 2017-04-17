#include "revoke.h"

int check_revoked(const PGPKey & key, std::string & error){
    if (!key.meaningful(error)){
        error += "Error: Bad Key.\n";
        return -1;
    }

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
        }
    }

    return false;
}

// Returns revocation signature packet
Tag2::Ptr revoke_sig(const Tag5::Ptr & signer, const std::string & passphrase, const Key::Ptr & target, Tag2::Ptr & sig, std::string & error){
    if (!signer){
        error += "Error: No key given.\n";
        return nullptr;
    }

    // TODO check if the signer is allowed to sign the target

    if (!target){
        error += "Error: No key given.\n";
        return nullptr;
    }

    if (!sig){
        error += "Error: No signature packet given.\n";
        return nullptr;
    }

    // only allow key and subkey revocation here
    if ((sig -> get_type() != Signature_Type::KEY_REVOCATION_SIGNATURE)   &&
        (sig -> get_type() != Signature_Type::SUBKEY_REVOCATION_SIGNATURE)){
        error += "Error: Bad revocation type.\n";
        return nullptr;
    }

    // set signature data
    std::string digest;
    if (sig -> get_type() == Signature_Type::KEY_REVOCATION_SIGNATURE){
        digest = to_sign_20(target, sig);
    }
    else if (sig -> get_type() == Signature_Type::SUBKEY_REVOCATION_SIGNATURE){
        digest = to_sign_28(target, sig);
    }

    sig -> set_left16(digest.substr(0, 2));
    PKA::Values vals = pka_sign(digest, signer -> get_pka(), signer -> decrypt_secret_keys(passphrase), signer -> get_mpi(), sig -> get_hash(), error);
    if (!vals.size()){
        error += "Error: PKA Signing failed.\n";
        return nullptr;
    }
    sig -> set_mpi(vals);

    return sig;
}

Tag2::Ptr revoke_key_sig(const RevArgs & args, std::string & error){
    if (!args.valid(error)){
        error += "Error: Bad arguments.\n";
        return nullptr;
    }

    // find signing key
    Tag5::Ptr signer = std::static_pointer_cast <Tag5> (find_signing_key(args.signer));
    if (!signer){
        error += "Error: No Secret Key packet found.\n";
        return nullptr;
    }

    // create signature packet to sign
    Tag2::Ptr sig = create_sig_packet(args.version, Signature_Type::KEY_REVOCATION_SIGNATURE, signer -> get_pka(), args.hash, signer -> get_keyid());
    if (!sig){
        error += "Error: Unable to create an empty signature packet.\n";
        return nullptr;
    }

    // add revocation subpacket
    std::vector <Tag2Subpacket::Ptr> hashed_subpackets = sig -> get_hashed_subpackets_clone();
    Tag2Sub29::Ptr revoke = std::make_shared <Tag2Sub29> ();
    revoke -> set_code(args.code);
    revoke -> set_reason(args.reason);
    hashed_subpackets.push_back(revoke);
    sig -> set_hashed_subpackets(hashed_subpackets);


    return revoke_sig(signer, args.passphrase, signer, sig, error);
}

Tag2::Ptr revoke_subkey_sig(const RevArgs & args, const std::string & keyid, std::string & error){
    if (!args.valid(error)){
        error += "Error: Bad arguments.\n";
        return nullptr;
    }

    // find signing key
    const Tag5::Ptr signer = std::static_pointer_cast <Tag5> (find_signing_key(args.signer));
    if (!signer){
        error += "Error: No Secret Key packet found.\n";
        return nullptr;
    }

    // find subkey to sign
    Tag7::Ptr target = nullptr;
    for(Packet::Ptr const & p : args.target.get_packets()){
        if (p -> get_tag() == Packet::SECRET_SUBKEY){
            target = std::static_pointer_cast <Tag7> (p);
            if (target -> get_keyid().find(keyid) != std::string::npos){
                break;
            }
            target = nullptr;
        }
    }

    if (!target){
        error += "Error: No subkey found.\n";
        return nullptr;
    }

    // create signature packet to sign
    Tag2::Ptr sig = create_sig_packet(args.version, Signature_Type::SUBKEY_REVOCATION_SIGNATURE, signer -> get_pka(), args.hash, signer -> get_keyid());
    if (!sig){
        error += "Error: Unable to create an empty signature packet.\n";
        return nullptr;
    }

    return revoke_sig(signer, args.passphrase, target, sig, error);
}

Tag2::Ptr revoke_uid_sig(const Tag5::Ptr & signer, const std::string & passphrase, const User::Ptr & user, Tag2::Ptr & sig, std::string & error){
    if (!signer){
        error += "Error: No signing key given.\n";
        return nullptr;
    }

    if (!user){
        error += "Error: No user packet given.\n";
        return nullptr;
    }

    if (!sig){
        error += "Error: No revocation signature packet given.\n";
        return nullptr;
    }

    if (sig -> get_type() != Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE){
        error += "Error: Revocation signature packet does not indicate a " + Signature_Type::NAME.at(Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE) + " (type " + std::to_string(Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE) + ").\n";
        return nullptr;
    }

    // set signature data
    std::string digest = to_sign_30(signer, user, sig);
    sig -> set_left16(digest.substr(0, 2));
    PKA::Values vals = pka_sign(digest, signer -> get_pka(), signer -> decrypt_secret_keys(passphrase), signer -> get_mpi(), sig -> get_hash(), error);
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

    const Tag5::Ptr signer = std::static_pointer_cast <Tag5> (find_signing_key(args.signer));
    if (!signer){
        error += "Error: Private signing key not found.\n";
        return nullptr;
    }

    // find user information
    User::Ptr user = nullptr;
    for(Packet::Ptr const & p : args.target.get_packets()){
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
    if (!sig){
        error += "Error: Could not generate revocation signature packet.\n";
        return nullptr;
    }

    // add revocation subpacket
    std::vector <Tag2Subpacket::Ptr> hashed_subpackets = sig -> get_hashed_subpackets_clone();
    Tag2Sub29::Ptr revoke = std::make_shared <Tag2Sub29> ();
    revoke -> set_code(args.code);
    revoke -> set_reason(args.reason);
    hashed_subpackets.push_back(revoke);
    sig -> set_hashed_subpackets(hashed_subpackets);

    return revoke_uid_sig(signer, args.passphrase, user, sig, error);
}

// creates revocation certificate to be used later
PGPRevocationCertificate revoke_key_cert(const RevArgs & args, std::string & error){
    Tag2::Ptr sig = revoke_key_sig(args, error);
    if (!sig){
        error += "Error: Could not generate revocation signature packet.\n";
        return PGPRevocationCertificate();
    }

    PGPRevocationCertificate signature;
    signature.set_keys({std::make_pair("Version", "cc"), std::make_pair("Comment", "Revocation Certificate")});
    signature.set_packets({sig});

    return signature;
}

PGPRevocationCertificate revoke_subkey_cert(const RevArgs & args, const std::string & keyid, std::string & error){
    Tag2::Ptr sig = revoke_subkey_sig(args, keyid, error);
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
PGPPublicKey revoke_key(const RevArgs & args, std::string & error){
    if (!args.valid(error)){
        error += "Error: Bad key.\n";
        return PGPPublicKey();
    }

    const Tag2::Ptr revoke_sig = revoke_key_sig(args, error);
    if (!revoke_sig){
        error += "Error: Could not revoke primary key.\n";
        return PGPPublicKey();
    }

    // Create output key packets
    const PGP::Packets & old_packets = args.target.get_packets();
    PGP::Packets new_packets;

    if (old_packets[0] -> get_tag() == Packet::PUBLIC_KEY){
        new_packets.push_back(old_packets[0] -> clone());
    }
    else if (old_packets[0] -> get_tag() == Packet::SECRET_KEY){
        new_packets.push_back(std::static_pointer_cast <Tag5> (old_packets[0]) -> get_public_ptr());
    }

    // push in revocation packet
    new_packets.push_back(revoke_sig -> clone());

    // append rest of packets
    unsigned int i = 1;
    while (i < old_packets.size()){
        // get public version of secret subkey
        if (old_packets[i] -> get_tag() == Packet::SECRET_SUBKEY){
            new_packets.push_back(std::static_pointer_cast <Tag7> (old_packets[i]) -> get_public_ptr());
        }
        else{
            new_packets.push_back(old_packets[i] -> clone());
        }
        i++;
    }

    PGPPublicKey revoked;
    revoked.set_keys(args.target.get_keys());
    revoked.set_packets(new_packets);

    return revoked;
}

PGPPublicKey revoke_subkey(const RevArgs & args, const std::string & keyid, std::string & error){
    if (!args.valid(error)){
        error += "Error: Bad key.\n";
        return PGPPublicKey();
    }

    const Tag2::Ptr revoke_sig = revoke_subkey_sig(args, keyid, error);
    if (!revoke_sig){
        error += "Error: Could not revoke primary key.\n";
        return PGPPublicKey();
    }

    // Create output key
    const PGP::Packets & old_packets = args.target.get_packets();
    PGP::Packets new_packets;

    if (old_packets[0] -> get_tag() == Packet::PUBLIC_KEY){
        new_packets.push_back(old_packets[0] -> clone());
    }
    else if (old_packets[0] -> get_tag() == Packet::SECRET_KEY){
        new_packets.push_back(std::static_pointer_cast <Tag5> (old_packets[0]) -> get_public_ptr());
    }

    // push all packets up to the first subkey
    unsigned int i = 1;
    while ((i < old_packets.size()) && !Packet::is_subkey(old_packets[i] -> get_tag())){
        new_packets.push_back(old_packets[i++] -> clone());
    }

    // append rest of packets
    while (i < old_packets.size()){
        if (old_packets[i] -> get_tag() == Packet::PUBLIC_SUBKEY){
            // no need to get public version
            new_packets.push_back(old_packets[i] -> clone());

            if (std::static_pointer_cast <Tag14> (old_packets[i]) -> get_keyid() == keyid){
                #ifndef GPG_COMPATIBLE
                // clone following signature packet
                new_packets.push_back(old_packets[++i] -> clone());
                #endif

                // push in revocation packet
                new_packets.push_back(revoke_sig -> clone());
            }
        }
        else if (old_packets[i] -> get_tag() == Packet::SECRET_SUBKEY){
            const Tag7::Ptr tag7 = std::static_pointer_cast <Tag7> (old_packets[i]);

            // push in public version
            new_packets.push_back(tag7 -> get_public_ptr());

            if (tag7 -> get_keyid() == keyid){
                #ifndef GPG_COMPATIBLE
                // clone following signature packet
                new_packets.push_back(old_packets[++i] -> clone());
                #endif

                // push in revocation packet
                new_packets.push_back(revoke_sig -> clone());
            }
        }
        else{
            new_packets.push_back(old_packets[i] -> clone());
        }

        i++;
    }

    PGPPublicKey revoked;
    revoked.set_keys(args.target.get_keys());
    revoked.set_packets(new_packets);

    return revoked;
}

PGPPublicKey revoke_uid(const RevArgs & args, const std::string & ID, std::string & error){
    if (!args.valid(error)){
        error += "Error: Bad arguments.\n";
        return PGPPublicKey();
    }

    if (args.signer.keyid() != args.target.keyid()){
        error += "Error: Certification Revocation Signature should be issued to self.\n";
        return PGPPublicKey();
    }

    const Tag2::Ptr revoke_cert = revoke_uid_sig(args, ID, error);
    if (!revoke_cert){
        error += "Error: Could not revoke certification.\n";
        return PGPPublicKey();
    }

    const PGP::Packets & old_packets = args.target.get_packets();
    PGP::Packets new_packets;

    if (old_packets[0] -> get_tag() == Packet::PUBLIC_KEY){
        new_packets.push_back(old_packets[0] -> clone());
    }
    else if (old_packets[0] -> get_tag() == Packet::SECRET_KEY){
        new_packets.push_back(std::static_pointer_cast <Tag5> (old_packets[0]) -> get_public_ptr());
    }

    // clone all packets
    unsigned int i = 1;
    while (i < old_packets.size()){
        if (old_packets[i] -> get_tag() == Packet::SECRET_SUBKEY){
            // push in public version
            new_packets.push_back(std::static_pointer_cast <Tag7> (old_packets[i]) -> get_public_ptr());
        }
        else if (old_packets[i] -> get_tag() == Packet::USER_ID){
            // make sure some part of the User ID matches the requested ID
            // this might result in multiple matches
            if (std::static_pointer_cast <Tag13> (old_packets[i]) -> get_contents().find(ID) != std::string::npos){
                new_packets.push_back(old_packets[i] -> clone());
                new_packets.push_back(revoke_cert);
            }
        }
        // else if (p -> get_tag() == Packet::USER_ATTRIBUTE){}
        else{
            new_packets.push_back(old_packets[i] -> clone());
        }

        i++;
    }

    PGPPublicKey revoked;
    revoked.set_keys(args.target.get_keys());
    revoked.set_packets(new_packets);

    return revoked;
}

PGPPublicKey revoke_with_cert(const PGPKey & key, const PGPRevocationCertificate & revoke, std::string & error){
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
    if (rc == false){
        error += "Error: Revocation certificate is not for key " + hexlify(key.keyid()) + "\n";
        return PGPPublicKey();
    }
    else if (rc == -1){
        error += "Error: verify_revoke failure.\n";
        return PGPPublicKey();
    }

    // extract revocation signature; don't need to check - should have been caught by revoke.meaningful()
    const Tag2::Ptr revoke_sig = std::static_pointer_cast <Tag2> (revoke.get_packets()[0]);

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

    unsigned int i = 1;

    // if the revocation was for a user packet, put it behind the user packet
    if (revoke_sig -> get_type() == Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE){
        // go to first user packet
        while ((i < old_packets.size()) && !Packet::is_user(old_packets[i] -> get_tag())){
            i++;
        }

        // search all user packets
        const Key::Ptr signing_key = std::static_pointer_cast <Key> (old_packets[0]);
        while ((i < old_packets.size()) && Packet::is_user(old_packets[i] -> get_tag())){
            const User::Ptr user = std::static_pointer_cast <User> (old_packets[i]);
            const int rc = pka_verify(to_sign_30(signing_key, user, revoke_sig), signing_key, revoke_sig, error);
            if (rc == true){
                new_packets.push_back(old_packets[i++] -> clone());
                new_packets.push_back(revoke_sig -> clone());
                i++;
                break;
            }
            else if (rc == -1){
                error += "Error: pka_verify failure.\n";
                return PGPPublicKey();
            }

            // ignore signatures
            while ((i < old_packets.size()) && (old_packets[i] -> get_tag() == Packet::SIGNATURE)){
                new_packets.push_back(old_packets[i++] -> clone());
            }
        }
    }

    // push all packets up to the subkey
    while ((i < old_packets.size()) && !Packet::is_subkey(old_packets[i] -> get_tag())){
        new_packets.push_back(old_packets[i++] -> clone());
    }

    // process the subkey
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

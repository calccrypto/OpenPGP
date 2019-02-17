#include "revoke.h"

namespace OpenPGP {
namespace Revoke {

// this probably needs fixing
int check(const Key & key){
    if (!key.meaningful()){
        // "Error: Bad Key.\n";
        return -1;
    }

    const PGP::Packets packets = key.get_packets();

    // primary key
    if (packets[1] -> get_tag() == Packet::SIGNATURE){
        Packet::Tag2::Ptr tag2 = std::static_pointer_cast <Packet::Tag2> (packets[1]);
        // if the signature packet is a key/subkey revocation signature
        if (tag2 -> get_type() == Signature_Type::KEY_REVOCATION_SIGNATURE){
            // TODO verify the signature/hash bits
            return true;
        }

        // "Error: Bad signature type.\n";
        return -1;
    }

    // UIDs and subkeys
    for(Packet::Tag::Ptr const & p: key.get_packets()){
        // if a signature packet
        if (p -> get_tag() == Packet::SIGNATURE){
            const Packet::Tag2::Ptr tag2 = std::static_pointer_cast <Packet::Tag2> (p);
            // if the signature packet is a key/subkey revocation signature
            if ((tag2 -> get_type() == Signature_Type::SUBKEY_REVOCATION_SIGNATURE)       ||
                (tag2 -> get_type() == Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE)){
                // TODO verify the signature/hash bits
                return true;
            }
        }
    }

    return false;
}

// Returns revocation signature packet
Packet::Tag2::Ptr sig(const Packet::Tag5::Ptr & signer, const std::string & passphrase, const Packet::Key::Ptr & target, Packet::Tag2::Ptr & sig){
    if (!signer){
        // "Error: No key given.\n";
        return nullptr;
    }

    // TODO check if the signer is allowed to sign the target

    if (!target){
        // "Error: No key given.\n";
        return nullptr;
    }

    if (!sig){
        // "Error: No signature packet given.\n";
        return nullptr;
    }

    // only allow key and subkey revocation here
    if ((sig -> get_type() != Signature_Type::KEY_REVOCATION_SIGNATURE)   &&
        (sig -> get_type() != Signature_Type::SUBKEY_REVOCATION_SIGNATURE)){
        // "Error: Bad revocation type.\n";
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
    PKA::Values vals = Sign::with_pka(digest, signer -> get_pka(), signer -> decrypt_secret_keys(passphrase), signer -> get_mpi(), sig -> get_hash());
    if (!vals.size()){
        // "Error: PKA Signing failed.\n";
        return nullptr;
    }
    sig -> set_mpi(vals);

    return sig;
}

Packet::Tag2::Ptr key_sig(const Args & args){
    if (!args.valid()){
        // "Error: Bad arguments.\n";
        return nullptr;
    }

    // find signing key
    Packet::Tag5::Ptr signer = std::static_pointer_cast <Packet::Tag5> (find_signing_key(args.signer));
    if (!signer){
        // "Error: No Secret Key packet found.\n";
        return nullptr;
    }

    // create signature packet to sign
    Packet::Tag2::Ptr sig = Sign::create_sig_packet(args.version, Signature_Type::KEY_REVOCATION_SIGNATURE, signer -> get_pka(), args.hash, signer -> get_keyid());
    if (!sig){
        // "Error: Unable to create an empty signature packet.\n";
        return nullptr;
    }

    // add revocation subpacket
    std::vector <Subpacket::Tag2::Sub::Ptr> hashed_subpackets = sig -> get_hashed_subpackets_clone();
    Subpacket::Tag2::Sub29::Ptr revoke = std::make_shared <Subpacket::Tag2::Sub29> ();
    revoke -> set_code(args.code);
    revoke -> set_reason(args.reason);
    hashed_subpackets.push_back(revoke);
    sig -> set_hashed_subpackets(hashed_subpackets);


    return Revoke::sig(signer, args.passphrase, signer, sig);
}

Packet::Tag2::Ptr subkey_sig(const Args & args, const std::string & keyid){
    if (!args.valid()){
        // "Error: Bad arguments.\n";
        return nullptr;
    }

    // find signing key
    const Packet::Tag5::Ptr signer = std::static_pointer_cast <Packet::Tag5> (find_signing_key(args.signer));
    if (!signer){
        // "Error: No Secret Key packet found.\n";
        return nullptr;
    }

    // find subkey to sign
    Packet::Tag7::Ptr target = nullptr;
    for(Packet::Tag::Ptr const & p : args.target.get_packets()){
        if (p -> get_tag() == Packet::SECRET_SUBKEY){
            target = std::static_pointer_cast <Packet::Tag7> (p);
            if (target -> get_keyid().find(keyid) != std::string::npos){
                break;
            }
            target = nullptr;
        }
    }

    if (!target){
        // "Error: No subkey found.\n";
        return nullptr;
    }

    // create signature packet to sign
    Packet::Tag2::Ptr sig = Sign::create_sig_packet(args.version, Signature_Type::SUBKEY_REVOCATION_SIGNATURE, signer -> get_pka(), args.hash, signer -> get_keyid());
    if (!sig){
        // "Error: Unable to create an empty signature packet.\n";
        return nullptr;
    }

    return Revoke::sig(signer, args.passphrase, target, sig);
}

Packet::Tag2::Ptr uid_sig(const Packet::Tag5::Ptr & signer, const std::string & passphrase, const Packet::User::Ptr & user, Packet::Tag2::Ptr & sig){
    if (!signer){
        // "Error: No signing key given.\n";
        return nullptr;
    }

    if (!user){
        // "Error: No user packet given.\n";
        return nullptr;
    }

    if (!sig){
        // "Error: No revocation signature packet given.\n";
        return nullptr;
    }

    if (sig -> get_type() != Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE){
        // "Error: Revocation signature packet does not indicate a " + Signature_Type::NAME.at(Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE) + " (type " + std::to_string(Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE) + ").\n";
        return nullptr;
    }

    // set signature data
    std::string digest = to_sign_30(signer, user, sig);
    sig -> set_left16(digest.substr(0, 2));
    PKA::Values vals = Sign::with_pka(digest, signer -> get_pka(), signer -> decrypt_secret_keys(passphrase), signer -> get_mpi(), sig -> get_hash());
    if (!vals.size()){
        // "Error: PKA Signing failed.\n";
        return nullptr;
    }
    sig -> set_mpi(vals);

    return sig;
}

Packet::Tag2::Ptr uid_sig(const Args & args, const std::string & ID){
    if (!args.valid()){
        // "Error: Bad arguments.\n";
        return nullptr;
    }

    const Packet::Tag5::Ptr signer = std::static_pointer_cast <Packet::Tag5> (find_signing_key(args.signer));
    if (!signer){
        // "Error: Private signing key not found.\n";
        return nullptr;
    }

    // find user information
    Packet::User::Ptr user = nullptr;
    for(Packet::Tag::Ptr const & p : args.target.get_packets()){
        if (p -> get_tag() == Packet::USER_ID){
            Packet::Tag13::Ptr tag13 = std::static_pointer_cast <Packet::Tag13> (p);

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
        // "Error: No user information matching \"" + ID + "\" found.\n";
        return nullptr;
    }

    Packet::Tag2::Ptr sig = Sign::create_sig_packet(args.version, Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE, signer -> get_pka(), args.hash, signer -> get_keyid());
    if (!sig){
        // "Error: Could not generate revocation signature packet.\n";
        return nullptr;
    }

    // add revocation subpacket
    std::vector <Subpacket::Tag2::Sub::Ptr> hashed_subpackets = sig -> get_hashed_subpackets_clone();
    Subpacket::Tag2::Sub29::Ptr revoke = std::make_shared <Subpacket::Tag2::Sub29> ();
    revoke -> set_code(args.code);
    revoke -> set_reason(args.reason);
    hashed_subpackets.push_back(revoke);
    sig -> set_hashed_subpackets(hashed_subpackets);

    return uid_sig(signer, args.passphrase, user, sig);
}

// creates revocation certificate to be used later
RevocationCertificate key_cert(const Args & args){
    Packet::Tag2::Ptr sig = key_sig(args);
    if (!sig){
        // "Error: Could not generate revocation signature packet.\n";
        return RevocationCertificate();
    }

    RevocationCertificate signature;
    signature.set_keys({std::make_pair("Version", "cc"), std::make_pair("Comment", "Revocation Certificate")});
    signature.set_packets({sig});

    return signature;
}

RevocationCertificate subkey_cert(const Args & args, const std::string & keyid){
    Packet::Tag2::Ptr sig = subkey_sig(args, keyid);
    if (!sig){
        // "Error: Could not generate revocation signature packet.\n";
        return RevocationCertificate();
    }

    RevocationCertificate signature;
    signature.set_keys({std::make_pair("Version", "cc"), std::make_pair("Comment", "Revocation Certificate")});
    signature.set_packets({sig});

    return signature;
}

RevocationCertificate uid_cert(const Args & args, const std::string & ID){
    Packet::Tag2::Ptr sig = uid_sig(args, ID);
    if (!sig){
        // "Error: Could not generate revocation signature packet.\n";
        return RevocationCertificate();
    }

    RevocationCertificate signature;
    signature.set_keys({std::make_pair("Version", "cc"), std::make_pair("Comment", "Revocation Certificate")});
    signature.set_packets({sig});

    return signature;
}

// Revoke with certificate
PublicKey with_cert(const Key & key, const RevocationCertificate & revoke){
    if (!key.meaningful()){
        // "Error: Bad key.\n";
        return PublicKey();
    }

    if (!revoke.meaningful()){
        // "Error: Bad revocation certificate.\n";
        return PublicKey();
    }

    // make sure that the revocation certificate is for the given key
    const int rc = Verify::revoke(key, revoke);
    if (rc == false){
        // "Error: Revocation certificate is not for key " + hexlify(key.keyid()) + "\n";
        return PublicKey();
    }
    else if (rc == -1){
        // "Error: verify_revoke failure.\n";
        return PublicKey();
    }

    // extract revocation signature; don't need to check - should have been caught by revoke.meaningful()
    const Packet::Tag2::Ptr sig = std::static_pointer_cast <Packet::Tag2> (revoke.get_packets()[0]);

    // Create output key
    const PGP::Packets & old_packets = key.get_packets();
    PGP::Packets new_packets;

    // process the primary key
    if (old_packets[0] -> get_tag() == Packet::PUBLIC_KEY){
        new_packets.push_back(old_packets[0] -> clone());
    }
    else if (old_packets[0] -> get_tag() == Packet::SECRET_KEY){
        new_packets.push_back(std::static_pointer_cast <Packet::Tag5> (old_packets[0]) -> get_public_ptr());
    }

    // if the revocation was for the primary key, put it behind the key packet
    if (sig -> get_type() == Signature_Type::KEY_REVOCATION_SIGNATURE){
        new_packets.push_back(sig -> clone());
    }

    unsigned int i = 1;

    // if the revocation was for a user packet, put it behind the user packet
    if (sig -> get_type() == Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE){
        // go to first user packet
        while ((i < old_packets.size()) && !Packet::is_user(old_packets[i] -> get_tag())){
            i++;
        }

        // search all user packets
        const Packet::Key::Ptr signing_key = std::static_pointer_cast <Packet::Key> (old_packets[0]);
        while ((i < old_packets.size()) && Packet::is_user(old_packets[i] -> get_tag())){
            const Packet::User::Ptr user = std::static_pointer_cast <Packet::User> (old_packets[i]);
            const int rc = Verify::with_pka(to_sign_30(signing_key, user, sig), signing_key, sig);
            if (rc == true){
                new_packets.push_back(old_packets[i++] -> clone());
                new_packets.push_back(sig -> clone());
                i++;
                break;
            }
            else if (rc == -1){
                // "Error: pka_verify failure.\n";
                return PublicKey();
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
        new_packets.push_back(std::static_pointer_cast <Packet::Tag7> (old_packets[i]) -> get_public_ptr());
    }

    i++;

    // if the revocation was for the subkey, find the signing packet and put the revocation signature after it
    if (sig -> get_type() == Signature_Type::SUBKEY_REVOCATION_SIGNATURE){
        #ifndef GPG_COMPATIBLE
        // clone following signature packet
        new_packets.push_back(old_packets[i++] -> clone());
        #endif

        // push revocation packet in
        new_packets.push_back(sig -> clone());
    }

    // append rest of packets
    while (i < old_packets.size()){
        new_packets.push_back(old_packets[i++] -> clone());
    }

    PublicKey revoked;
    revoked.set_keys(key.get_keys());
    revoked.set_packets(new_packets);

    return revoked;
}

// Directly Revoke (does not write to key; instead, returns new copy of public key)
PublicKey key(const Args & args){
    if (!args.valid()){
        // "Error: Bad key.\n";
        return PublicKey();
    }

    const Packet::Tag2::Ptr sig = key_sig(args);
    if (!sig){
        // "Error: Could not revoke primary key.\n";
        return PublicKey();
    }

    // Create output key packets
    const PGP::Packets & old_packets = args.target.get_packets();
    PGP::Packets new_packets;

    if (old_packets[0] -> get_tag() == Packet::PUBLIC_KEY){
        new_packets.push_back(old_packets[0] -> clone());
    }
    else if (old_packets[0] -> get_tag() == Packet::SECRET_KEY){
        new_packets.push_back(std::static_pointer_cast <Packet::Tag5> (old_packets[0]) -> get_public_ptr());
    }

    // push in revocation packet
    new_packets.push_back(sig -> clone());

    // append rest of packets
    unsigned int i = 1;
    while (i < old_packets.size()){
        // get public version of secret subkey
        if (old_packets[i] -> get_tag() == Packet::SECRET_SUBKEY){
            new_packets.push_back(std::static_pointer_cast <Packet::Tag7> (old_packets[i]) -> get_public_ptr());
        }
        else{
            new_packets.push_back(old_packets[i] -> clone());
        }
        i++;
    }

    PublicKey revoked;
    revoked.set_keys(args.target.get_keys());
    revoked.set_packets(new_packets);

    return revoked;
}

PublicKey subkey(const Args & args, const std::string & keyid){
    if (!args.valid()){
        // "Error: Bad key.\n";
        return PublicKey();
    }

    const Packet::Tag2::Ptr sig = subkey_sig(args, keyid);
    if (!sig){
        // "Error: Could not revoke primary key.\n";
        return PublicKey();
    }

    // Create output key
    const PGP::Packets & old_packets = args.target.get_packets();
    PGP::Packets new_packets;

    if (old_packets[0] -> get_tag() == Packet::PUBLIC_KEY){
        new_packets.push_back(old_packets[0] -> clone());
    }
    else if (old_packets[0] -> get_tag() == Packet::SECRET_KEY){
        new_packets.push_back(std::static_pointer_cast <Packet::Tag5> (old_packets[0]) -> get_public_ptr());
    }

    // push all packets up to the first subkey
    unsigned int i = 1;
    while ((i < old_packets.size()) && !Packet::is_subkey(old_packets[i] -> get_tag())){
        new_packets.push_back(old_packets[i++] -> clone());
    }

    // append rest of packets
    while (i < old_packets.size()){
        if (Packet::is_subkey(old_packets[i] -> get_tag())){
            if (old_packets[i] -> get_tag() == Packet::SECRET_SUBKEY){
                // push in public version
                new_packets.push_back(std::static_pointer_cast <Packet::Tag7> (old_packets[i]) -> get_public_ptr());
            }
            else{
                // no need to get public version
                new_packets.push_back(old_packets[i] -> clone());
            }

            if (std::static_pointer_cast <Packet::Tag14> (old_packets[i]) -> get_keyid().find(keyid) != std::string::npos){
                #ifndef GPG_COMPATIBLE
                // clone following signature packet
                new_packets.push_back(old_packets[++i] -> clone());
                #endif

                // push in revocation packet
                new_packets.push_back(sig -> clone());
            }
        }
        else{
            new_packets.push_back(old_packets[i] -> clone());
        }

        i++;
    }

    PublicKey revoked;
    revoked.set_keys(args.target.get_keys());
    revoked.set_packets(new_packets);

    return revoked;
}

PublicKey uid(const Args & args, const std::string & ID){
    if (!args.valid()){
        // "Error: Bad arguments.\n";
        return PublicKey();
    }

    if (args.signer.keyid() != args.target.keyid()){
        // "Error: Certification Revocation Signature should be issued to self.\n";
        return PublicKey();
    }

    const Packet::Tag2::Ptr cert = uid_sig(args, ID);
    if (!cert){
        // "Error: Could not revoke certification.\n";
        return PublicKey();
    }

    const PGP::Packets & old_packets = args.target.get_packets();
    PGP::Packets new_packets;

    if (old_packets[0] -> get_tag() == Packet::PUBLIC_KEY){
        new_packets.push_back(old_packets[0] -> clone());
    }
    else if (old_packets[0] -> get_tag() == Packet::SECRET_KEY){
        new_packets.push_back(std::static_pointer_cast <Packet::Tag5> (old_packets[0]) -> get_public_ptr());
    }

    // clone all packets
    unsigned int i = 1;
    while (i < old_packets.size()){
        if (old_packets[i] -> get_tag() == Packet::SECRET_SUBKEY){
            // push in public version
            new_packets.push_back(std::static_pointer_cast <Packet::Tag7> (old_packets[i]) -> get_public_ptr());
        }
        else if (old_packets[i] -> get_tag() == Packet::USER_ID){
            // make sure some part of the User ID matches the requested ID
            // this might result in multiple matches
            if (std::static_pointer_cast <Packet::Tag13> (old_packets[i]) -> get_contents().find(ID) != std::string::npos){
                new_packets.push_back(old_packets[i] -> clone());
                new_packets.push_back(cert);
            }
        }
        // else if (p -> get_tag() == Packet::USER_ATTRIBUTE){}
        else{
            new_packets.push_back(old_packets[i] -> clone());
        }

        i++;
    }

    PublicKey revoked;
    revoked.set_keys(args.target.get_keys());
    revoked.set_packets(new_packets);

    return revoked;
}

}
}
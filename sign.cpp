#include "sign.h"

namespace OpenPGP {
namespace Sign {

PKA::Values with_pka(const std::string & digest, const uint8_t pka, const PKA::Values & pri, const PKA::Values & pub, const uint8_t hash){
    if ((pka == PKA::ID::RSA_ENCRYPT_OR_SIGN) ||
        (pka == PKA::ID::RSA_ENCRYPT_ONLY)){
        // RFC 4880 sec 5.2.2
        // If RSA, hash value is encoded using EMSA-PKCS1-v1_5
        return {PKA::RSA::sign(EMSA_PKCS1_v1_5(hash, digest, bitsize(pub[0]) >> 3), pri, pub)};
    }
    else if (pka == PKA::ID::DSA){
        return PKA::DSA::sign(digest, pri, pub);
    }

    // "Error: Undefined or incorrect PKA number: " + std::to_string(pka) + "\n";
    return {};
}

Packet::Tag2::Ptr create_sig_packet(const uint8_t version, const uint8_t type, const uint8_t pka, const uint8_t hash, const std::string & keyid){
    // Set up signature packet
    Packet::Tag2::Ptr tag2 = std::make_shared <Packet::Tag2> ();
    tag2 -> set_version(version);
    tag2 -> set_pka(pka);
    tag2 -> set_type(type);
    tag2 -> set_hash(hash);

    // Set Time
    Subpacket::Tag2::Sub2::Ptr tag2sub2 = std::make_shared <Subpacket::Tag2::Sub2> ();
    tag2sub2 -> set_time(now());
    tag2 -> set_hashed_subpackets({tag2sub2});

    // Set Key ID
    Subpacket::Tag2::Sub16::Ptr tag2sub16 = std::make_shared <Subpacket::Tag2::Sub16> ();
    tag2sub16 -> set_keyid(keyid);
    tag2 -> set_unhashed_subpackets({tag2sub16});

    return tag2;
}

DetachedSignature detached_signature(const Args & args, const std::string & data){
    if (!args.valid()){
        // "Error: Bad argument.\n";
        return DetachedSignature();
    }

    Packet::Tag5::Ptr signer = std::static_pointer_cast <Packet::Tag5> (find_signing_key(args.pri));
    if (!signer){
        // "Error: No Private Key for signing found.\n";
        return DetachedSignature();
    }

    // Check if key has been revoked
    const int rc = Revoke::check(args.pri);
    if (rc == true){
        // "Error: Key " + hexlify(signer -> get_keyid()) + " has been revoked. Nothing done.\n";
        return DetachedSignature();
    }
    else if (rc == -1){
        // "Error: Revoke::check failed.\n";
        return DetachedSignature();
    }

    // create Signature Packet
    Packet::Tag2::Ptr sig = create_sig_packet(args.version, Signature_Type::SIGNATURE_OF_A_BINARY_DOCUMENT, signer -> get_pka(), args.hash, signer -> get_keyid());
    const std::string digest = to_sign_00(binary_to_canonical(data), sig);
    sig -> set_left16(digest.substr(0, 2));
    PKA::Values vals = with_pka(digest, signer -> get_pka(), signer -> decrypt_secret_keys(args.passphrase), signer -> get_mpi(), args.hash);
    if (!vals.size()){
        // "Error: PKA Signing failed.\n";
        return DetachedSignature();
    }
    sig -> set_mpi(vals);

    DetachedSignature signature;
    signature.set_keys({std::make_pair("Version", "cc")});
    signature.set_packets({sig});

    return signature;
}

// 0x00: Signature of a binary document.
Message binary(const Args & args, const std::string & filename, const std::string & data, const uint8_t compress){
    if (!args.valid()){
        // "Error: Bad argument.\n";
        return DetachedSignature();
    }

    // find signing key
    Packet::Tag5::Ptr signer = std::static_pointer_cast <Packet::Tag5> (find_signing_key(args.pri));
    if (!signer){
        // "Error: No signing key found.\n";
        return Message();
    }

    // create One-Pass Signature Packet
    Packet::Tag4::Ptr tag4 = std::make_shared <Packet::Tag4> ();
    tag4 -> set_type(0);
    tag4 -> set_hash(args.hash);
    tag4 -> set_pka(signer -> get_pka());
    tag4 -> set_keyid(signer -> get_keyid());
    tag4 -> set_nested(1); // 1 for no nesting

    // put source data into Literal Data Packet
    Packet::Tag11::Ptr tag11 = std::make_shared <Packet::Tag11> ();
    tag11 -> set_format('b');
    tag11 -> set_filename(filename);
    tag11 -> set_time(now());
    tag11 -> set_literal(data);

    // sign data
    Packet::Tag2::Ptr sig = create_sig_packet(args.version, Signature_Type::SIGNATURE_OF_A_BINARY_DOCUMENT, signer -> get_pka(), args.hash, signer -> get_keyid());
    const std::string digest = to_sign_00(binary_to_canonical(tag11 -> get_literal()), sig);
    sig -> set_left16(digest.substr(0, 2));
    PKA::Values vals = with_pka(digest, signer -> get_pka(), signer -> decrypt_secret_keys(args.passphrase), signer -> get_mpi(), args.hash);
    if (!vals.size()){
        // "Error: PKA Signing failed.\n";
        return Message();
    }
    sig -> set_mpi(vals);

    // put everything together
    Message signature;
    signature.set_keys({std::make_pair("Version", "cc")});
    signature.set_packets({tag4, tag11, sig});

    if (compress){ // only use a Compressed Data Packet if compression was used; don't bother for uncompressed data
        Packet::Tag8 tag8;
        tag8.set_data(signature.raw());
        tag8.set_comp(compress);
        std::string raw = tag8.write(Packet::Tag::Format::NEW);
        signature = Message(raw);
    }

    return signature;
}

// 0x01: Signature of a canonical text document.
CleartextSignature cleartext_signature(const Args & args, const std::string & text){
    if (!args.valid()){
        // "Error: Bad argument.\n";
        return CleartextSignature();
    }

    // find signing key
    Packet::Tag5::Ptr signer = std::static_pointer_cast <Packet::Tag5> (find_signing_key(args.pri));
    if (!signer){
        // "Error: No signing key found.\n";
        return CleartextSignature();
    }

    // create signature
    Packet::Tag2::Ptr sig = create_sig_packet(args.version, Signature_Type::SIGNATURE_OF_A_CANONICAL_TEXT_DOCUMENT, signer -> get_pka(), args.hash, signer -> get_keyid());
    const std::string digest = to_sign_01(CleartextSignature::data_to_text(text), sig);
    sig -> set_left16(digest.substr(0, 2));
    PKA::Values vals = with_pka(digest, signer -> get_pka(), signer -> decrypt_secret_keys(args.passphrase), signer -> get_mpi(), args.hash);
    if (!vals.size()){
        // "Error: PKA Signing failed.\n";
        return CleartextSignature();
    }
    sig -> set_mpi(vals);

    // put signature into Detached Signature
    DetachedSignature signature;
    signature.set_keys({std::make_pair("Version", "cc")});
    signature.set_packets({sig});

    // put signature under cleartext
    CleartextSignature message;
    message.set_hash_armor_header({std::make_pair("Hash", Hash::NAME.at(args.hash))});
    message.set_message(text);
    message.set_sig(signature);

    return message;
}

// 0x02: Standalone signature.

// 0x10: Generic certification of a User ID and Public-Key packet.
// 0x11: Persona certification of a User ID and Public-Key packet.
// 0x12: Casual certification of a User ID and Public-Key packet.
// 0x13: Positive certification of a User ID and Public-Key packet.
Packet::Tag2::Ptr primary_key(const Packet::Tag5::Ptr signer_signing_key, const std::string & passphrase, const Packet::Key::Ptr & signee_primary_key, const Packet::User::Ptr & signee_id, Packet::Tag2::Ptr & sig){
    if (!signer_signing_key){
        // "Error: No signing key given.\n";
        return nullptr;
    }

    if (!signee_primary_key){
        // "Error: No signee primary key given.\n";
        return nullptr;
    }

    if (!Packet::is_primary_key(signee_primary_key -> get_tag())){
        // "Error: signee key is not a primary key.\n";
        return nullptr;
    }

    if (!signee_id){
        // "Error: No User Identifier given.\n";
        return nullptr;
    }

    if (!sig){
        // "Error: No signature data given.\n";
        return nullptr;
    }

    if (!Signature_Type::is_certification(sig -> get_type())){
        // "Error: Invalid Certification Value: 0x" + makehex(sig -> get_type(), 2) + "\n";
        return nullptr;
    }

    const std::string digest = to_sign_cert(sig -> get_type(), signee_primary_key, signee_id, sig);
    sig -> set_left16(digest.substr(0, 2));
    PKA::Values vals = with_pka(digest, signer_signing_key -> get_pka(), signer_signing_key -> decrypt_secret_keys(passphrase), signer_signing_key -> get_mpi(), sig -> get_hash());
    if (!vals.size()){
        // "Error: PKA Signing failed.\n";
        return nullptr;
    }
    sig -> set_mpi(vals);

    return sig;
}

PublicKey primary_key(const Args & args, const PublicKey & signee, const std::string & user, const uint8_t cert){
    if (!args.valid()){
        // "Error: Bad arguments.\n";
        return PublicKey();
    }

    // check if signer has already been revoked
    if (Revoke::check(args.pri)){
        // "Error: Signer key is revoked. Nothing done.\n";
        return PublicKey();
    }

    if (!signee.meaningful()){
        // "Error: Bad signee key.\n";
        return PublicKey();
    }

    if (Revoke::check(signee)){
        // "Error: Signer key is revoked. Nothing done.\n";
        return PublicKey();
    }

    if (!Signature_Type::is_certification(cert)){
        // "Error: Invalid Certification Value: 0x" + makehex(cert, 2) + "\n";
        return PublicKey();
    }

    // get signer's signing packet
    Packet::Tag5::Ptr signer_signing_key = std::static_pointer_cast <Packet::Tag5> (find_signing_key(args.pri));
    if (!signer_signing_key){
        // "Error: Signing key not found.\n";
        return PublicKey();
    }

    const PGP::Packets & signee_packets = signee.get_packets();
    Packet::Key::Ptr signee_primary_key = std::static_pointer_cast <Packet::Key> (signee_packets[0]);
    Packet::User::Ptr signee_id = nullptr;

    // find matching user identifier
    PGP::Packets::size_type i = 1;
    do{
        // find matching user identifier
        if (Packet::is_user(signee_packets[i] -> get_tag())){
            // if the packet is a User ID
            if (signee_packets[i] -> get_tag() == Packet::USER_ID){
                Packet::Tag13::Ptr tag13 = std::static_pointer_cast <Packet::Tag13> (signee_packets[i]);
                if (tag13 -> get_contents().find(user) != std::string::npos){
                    signee_id = tag13;
                    i++; // go past User ID packet
                    break;
                }
            }
            // else if (signee_packets[i] -> get_tag() == Packet::USER_ATTRIBUTE){}
        }

        i++;
    } while (i < signee_packets.size());

    if (!signee_id){
        // "Error: No Signee user ID found.\n";
        return PublicKey();
    }

    // search through signatures to see signer has already certified this user
    while (i < signee_packets.size() && (signee_packets[i] -> get_tag() == Packet::SIGNATURE)){
        const int rc = Verify::primary_key(signer_signing_key, signee_primary_key, signee_id, std::static_pointer_cast <Packet::Tag2> (signee_packets[i]));
        if (rc == -1){
            // "Error: Signature verification failure.\n";
            return PublicKey();
        }
        else if (rc == true){
            std::cerr << "Warning: Primary Key and User ID have already been signed by " << args.pri << std::endl;
            return signee;
        }

        i++;
    }

    // sign key
    Packet::Tag2::Ptr sig = create_sig_packet(args.version, cert, signer_signing_key -> get_pka(), args.hash, signer_signing_key -> get_keyid());
    if (!sig){
        // "Error: Signature packet generation failure.\n";
        return PublicKey();
    }

    sig = primary_key(signer_signing_key, args.passphrase, signee_primary_key, signee_id, sig);
    if (!sig){
        // "Error: Signature calculation failure.\n";
        return PublicKey();
    }

    // Create output key
    PublicKey out(signee);
    PGP::Packets out_packets;

    // push all packets up to and including out packet into new packets
    PGP::Packets::size_type j;
    for(j = 0; j < (signee_packets.size()) && (j < i); j++){
        out_packets.push_back(signee_packets[j]);
    }

    // append signature to signatures following key
    out_packets.push_back(sig);

    // append rest of packets
    while (j < signee_packets.size()){
        out_packets.push_back(signee_packets[j++]);
    }

    out.set_packets(out_packets);

    return out;
}

// 0x18: Subkey Binding Signature
Packet::Tag2::Ptr subkey_binding(const Packet::Tag5::Ptr & primary, const std::string & passphrase, const Packet::Tag7::Ptr & sub, Packet::Tag2::Ptr & sig){
    if (!primary){
        // "Error: No primary key.\n";
        return nullptr;
    }

    if (!sub){
        // "Error: No subkey.\n";
        return nullptr;
    }

    if (!sig){
        // "Error: No signature.\n";
        return nullptr;
    }

    const std::string digest = to_sign_18(primary, sub, sig);
    sig -> set_left16(digest.substr(0, 2));
    PKA::Values vals = with_pka(digest, primary -> get_pka(), primary -> decrypt_secret_keys(passphrase), primary -> get_mpi(), sig -> get_hash());
    if (!vals.size()){
        // "Error: PKA Signing failed.\n";
        return nullptr;
    }
    sig -> set_mpi(vals);

    return sig;
}

// 0x19: Primary Key Binding Signature
Packet::Tag2::Ptr primary_key_binding(const Args & args, const PublicKey & signee){
    if (!args.valid()){
        // "Error: Bad arguments.\n";
        return nullptr;
    }

    // find signing subkey
    Packet::Tag5::Ptr subkey = std::static_pointer_cast <Packet::Tag5> (find_signing_key(args.pri));
    if (!subkey){
        // "Error: No Signing Subkey found.\n";
        return nullptr;
    }

    // move subkey data into subkey packet
    Packet::Tag7::Ptr signer_subkey = std::static_pointer_cast <Packet::Tag7> (subkey);

    // get signee primary and subkey
    Packet::Tag6::Ptr signee_primary = nullptr;
    for(Packet::Tag::Ptr const & p : args.pri.get_packets()){
        if (p -> get_tag() == Packet::PUBLIC_KEY){
            signee_primary = std::static_pointer_cast <Packet::Tag6> (p);
            break;
        }
    }

    if (!signee_primary){
        // "Error: Signee Primary Key not found.\n";
        return nullptr;
    }

    Packet::Tag14::Ptr signee_subkey = nullptr;
    for(Packet::Tag::Ptr const & p : args.pri.get_packets()){
        if (p -> get_tag() == Packet::PUBLIC_SUBKEY){
            signee_subkey = std::static_pointer_cast <Packet::Tag14> (p);
            break;
        }
    }

    if (!signee_subkey){
        // "Error: Singee Subkey not found.\n";
        return nullptr;
    }

    Packet::Tag2::Ptr sig = create_sig_packet(args.version, Signature_Type::PRIMARY_KEY_BINDING_SIGNATURE, signer_subkey -> get_pka(), args.hash, signer_subkey -> get_keyid());
    if (!sig){
        // "Error: Signature packet generation failure.\n";
        return nullptr;
    }

    const std::string digest = to_sign_18(signee_primary, signer_subkey, sig);
    sig -> set_left16(digest.substr(0, 2));
    PKA::Values vals = with_pka(digest, signer_subkey -> get_pka(), signer_subkey -> decrypt_secret_keys(args.passphrase), signer_subkey -> get_mpi(), args.hash);
    if (!vals.size()){
        // "Error: PKA Signing failed.\n";
        return nullptr;
    }
    sig -> set_mpi(vals);

    return sig;
}

DetachedSignature timestamp(const Args & args, const uint32_t time){
    if (!args.valid()){
        // "Error: Bad arguments.\n";
        return DetachedSignature();
    }

    Packet::Tag5::Ptr signer = std::static_pointer_cast <Packet::Tag5> (find_signing_key(args.pri));
    if (!signer){
        // "Error: Signing key not found.\n";
        return DetachedSignature();
    }

    Packet::Tag2::Ptr sig = create_sig_packet(args.version, Signature_Type::TIMESTAMP_SIGNATURE, signer -> get_pka(), args.hash, signer -> get_keyid());
    if (!sig){
        // "Error: Signature packet generation failure.\n";
        return DetachedSignature();
    }

    Subpacket::Tag2::Sub2::Ptr tag2sub2 = std::make_shared <Subpacket::Tag2::Sub2> ();
    tag2sub2 -> set_time(time);
    sig -> set_hashed_subpackets({tag2sub2});

    const std::string digest = to_sign_40(sig);
    sig -> set_left16(digest.substr(0, 2));
    PKA::Values vals = with_pka(digest, signer -> get_pka(), signer -> decrypt_secret_keys(args.passphrase), signer -> get_mpi(), args.hash);
    if (!vals.size()){
        // "Error: PKA Signing failed.\n";
        return DetachedSignature();
    }
    sig -> set_mpi(vals);

    DetachedSignature timestamp;
    timestamp.set_keys({std::make_pair("Version", "cc")});
    timestamp.set_packets({sig});

    return timestamp;
}

}
}
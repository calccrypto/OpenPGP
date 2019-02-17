#include "verify.h"

namespace OpenPGP {
namespace Verify {

int with_pka(const std::string & digest, const uint8_t hash, const uint8_t pka, const PKA::Values & signer, const PKA::Values & signee){
    if ((pka == PKA::ID::RSA_ENCRYPT_OR_SIGN) ||
        (pka == PKA::ID::RSA_SIGN_ONLY)){
        // RFC 4880 sec 5.2.2
        // If RSA, hash value is encoded using EMSA-PKCS1-v1_5
        return PKA::RSA::verify(EMSA_PKCS1_v1_5(hash, digest, bitsize(signer[0]) >> 3), signee, signer);
    }
    else if (pka == PKA::ID::DSA){
        return PKA::DSA::verify(digest, signee, signer);
    }

    // "Error: Bad PKA value.\n";
    return -1;
}

int with_pka(const std::string & digest, const Packet::Key::Ptr & signer, const Packet::Tag2::Ptr & signee){
    return with_pka(digest, signee -> get_hash(), signee -> get_pka(), signer -> get_mpi(), signee -> get_mpi());
}

int detached_signature(const Key & key, const std::string & data, const DetachedSignature & sig){
    if (!key.meaningful()){
        // "Error: Bad PGP Key.\n";
        return -1;
    }

    if (!sig.meaningful()){
        // "Error: Bad detached signature.\n";
        return -1;
    }

    const Packet::Tag2::Ptr signature = std::static_pointer_cast <Packet::Tag2> (sig.get_packets()[0]);

    // find key id in signature
    const std::string keyid = signature -> get_keyid();
    if (!keyid.size()){
        // "Error: No Key ID subpacket found.\n";
        return -1;
    }

    // make sure the key ID on the signature matches the Key's ID
    if (key.keyid() != keyid){
        return false;
    }

    // calculate the digest of the data (treated as binary)
    // and check the left 16 bits
    const std::string digest = to_sign_00(binary_to_canonical(data), signature);
    if (digest.substr(0, 2) != signature -> get_left16()){
        // "Hash digest and given left 16 bits of hash do not match.\n";
        return false;
    }

    // get signing key
    const Packet::Key::Ptr signing_key = find_signing_key(key);
    if (!signing_key){
        // "Error: No public signing keys found.\n";
        return -1;
    }

    return with_pka(digest, signing_key, signature);
}

// 0x00: Signature of a binary document.
int binary(const Key & key, const Message & message){
    if (!key.meaningful()){
        // "Error: Bad PGP Key.\n";
        return -1;
    }

    if (!message.meaningful()){
        // "Error: Bad message.\n";
        return -1;
    }

    // most of the time OpenPGP Message data is compressed
    // then it is encrypted

    if (message.match(Message::ENCRYPTEDMESSAGE)){
        // Encrypted Message :- Encrypted Data | ESK Sequence, Encrypted Data.
        // "Error: Use decrypt to verify message.\n";
        return -1;
    }

    if (message.match(Message::SIGNEDMESSAGE)){
        // Signed Message :- Signature Packet, OpenPGP Message | One-Pass Signed Message.

        const PGP::Packets packets = message.get_packets();

        if ((packets.size() > 2)                                         &&
            (packets.front() -> get_tag() == Packet::ONE_PASS_SIGNATURE) &&
            (packets.back() -> get_tag() == Packet::SIGNATURE)){
            // One-Pass Signed Message :- One-Pass Signature Packet, OpenPGP Message, Corresponding Signature Packet.

            // 5.4. One-Pass Signature Packets (Tag 4)
            //    Note that if a message contains more than one one-pass signature,
            //    then the Signature packets bracket the message; that is, the first
            //    Signature packet after the message corresponds to the last one-pass
            //    packet and the final Signature packet corresponds to the first
            //    one-pass packet.
            //
            //    Tag4_0,
            //        Tag4_1,
            //            ... ,
            //                Tag4_n,
            //                    Tag8/11,
            //                Tag2_n,
            //            ... ,
            //        Tag2_1,
            //    Tag2_0

            // get signing key
            const Packet::Key::Ptr signing_key = find_signing_key(key);
            if (!signing_key){
                // "Error: No public signing keys found.\n";
                return -1;
            }

            // get One-Pass Signature Packet(s) end + 1
            PGP::Packets::size_type OPSP = 0;
            while ((OPSP < packets.size()) && (packets[OPSP] -> get_tag() == Packet::ONE_PASS_SIGNATURE)){
                OPSP++;
            }
            if (OPSP == packets.size()){
                // "Error: No OpenPGP Message.\n";
                return -1;
            }

            // OpenPGP Message in the center
            PGP::Packets::size_type msg = OPSP;
            if (msg >= packets.size()){
                // "Error: OpenPGP Message not found.\n";
                return -1;
            }

            // get Signature Packet(s) start
            PGP::Packets::size_type SP = packets.size() - OPSP--;
            if (SP < OPSP){
                // "Error: Wrong number of packets.\n";
                return -1;
            }

            // find signature with matching keyid
            while (SP < packets.size()){
                if (std::static_pointer_cast <Packet::Tag4> (packets[OPSP]) -> get_keyid() == signing_key -> get_keyid()){
                    // build signed data
                    std::string binary = "";
                    for(PGP::Packets::size_type i = msg; i < SP; i++){
                        // actually only expects 1 literal data packet
                        if (packets[i] -> get_tag() == Packet::LITERAL_DATA){
                            binary += binary_to_canonical(std::static_pointer_cast <Packet::Tag11> (packets[i]) -> get_literal());
                        }
                        else{
                            binary += packets[i] -> raw();
                        }
                    }

                    // do verification
                    const Packet::Tag2::Ptr sig = std::static_pointer_cast <Packet::Tag2> (packets[SP]);
                    const int rc = with_pka(to_sign_00(binary, sig), signing_key, sig);
                    if (rc == -1){
                        // "Error: PKA verify failure.\n";
                        return -1;
                    }
                    else if (rc == true){
                        return true;
                    }
                }

                OPSP--;
                SP++;
            }

            return false;
        }
        else if (packets.size() &&
                 (packets.front() -> get_tag() == Packet::SIGNATURE)){
            // Signature Packet, OpenPGP Message
            // "Error: Signature Packet + OpenPGP Message signature not implmented.\n";
            return -1;
        }

        // "Error: Bad Signed Message.\n";
        return -1;
    }

    // this should never happen, because Message automatically decompresses
    if (message.match(Message::COMPRESSEDMESSAGE)){
        // Compressed Message :- Compressed Data Packet.
        return binary(key, Message(std::static_pointer_cast <Packet::Tag8> (message.get_packets()[0]) -> get_data()));
    }

    if (message.match(Message::LITERALMESSAGE)){
        // Literal Message :- Literal Data Packet.
        // return binary(key, Message(std::static_pointer_cast <Packet::Tag11> (message.get_packets()[0]) -> get_literal()));
        return true;
    }

    // "Error: Not an OpenPGP Message. Perhaps Detached Signature?\n";
    return -1;
}

// Signature type 0x01
int cleartext_signature(const Key & key, const CleartextSignature & message){
    if (!key.meaningful()){
        // "Error: Bad PGP Key.\n";
        return -1;
    }

    if (!message.meaningful()){
        // "Error: A Cleartext Signature is needed.\n";
        return -1;
    }

    // find key id from signature to match with public key
    Packet::Tag2::Ptr signature = std::static_pointer_cast <Packet::Tag2> (message.get_sig().get_packets()[0]);
    if (!signature){
        // "Error: No signature found.\n";
        return -1;
    }

    // find key id in signature
    std::string keyid = signature -> get_keyid();
    if (!keyid.size()){
        // "Error: No Key ID subpacket found.\n";
        return -1;
    }

    // make sure the key ID on the signature matches the Key's ID
    if (key.keyid() != keyid){
        return false;
    }

    // calculate the digest of the cleartext data (trailing whitespace removed)
    // and check the left 16 bits
    const std::string digest = to_sign_01(message.data_to_text(), signature);
    if (digest.substr(0, 2) != signature -> get_left16()){
        // "Hash digest and given left 16 bits of hash do not match.\n";
        return -1;
    }

    // get signing key
    const Packet::Key::Ptr signing_key = find_signing_key(key);
    if (!signing_key){
        // "Error: No public signing keys found.\n";
        return -1;
    }

    return with_pka(digest, signing_key, signature);
}

// 0x02: Standalone signature.

// 0x10: Generic certification of a User ID and Public-Key packet.
// 0x11: Persona certification of a User ID and Public-Key packet.
// 0x12: Casual certification of a User ID and Public-Key packet.
// 0x13: Positive certification of a User ID and Public-Key packet.
int primary_key(const Packet::Key::Ptr & signer_key, const Packet::Key::Ptr & signee_key, const Packet::User::Ptr & signee_id, const Packet::Tag2::Ptr & signee_signature){
    // if the signing key's ID doesn't match with the signature's ID
    if ((signer_key -> get_keyid() != signee_signature -> get_keyid())){
        return false;
    }

    // check if the signature is valid
    return with_pka(to_sign_cert(signee_signature -> get_type(), signee_key, signee_id, signee_signature), signer_key, signee_signature);
}

int primary_key(const Key & signer, const Key & signee){
    if (!signer.meaningful()){
        // "Error: Bad Signer Key.\n";
        return -1;
    }

    if (!signee.meaningful()){
        // "Error: Bad Signee Key.\n";
        return -1;
    }

    // get signer's key id
    const std::string signer_keyid = signer.keyid();
    if (!signer_keyid.size()){
        // "Error: Signer key does not have a key id.\n";
        return -1;
    }

    // get signing key
    const Packet::Key::Ptr signer_key = find_signing_key(signer);
    if (!signer_key){
        // "Error: No signing keys found.\n";
        return -1;
    }

    // keep track of Key and UID being verified
    Packet::Key::Ptr signee_key = nullptr;
    Packet::User::Ptr signee_id = nullptr;

    // for each signature packet on the signee
    for(Packet::Tag::Ptr const & signee_packet : signee.get_packets()){
        if (Packet::is_primary_key(signee_packet -> get_tag())){
            signee_key = std::static_pointer_cast <Packet::Key> (signee_packet);
            signee_id = nullptr;        // need to find new User information
        }
        else if (Packet::is_user(signee_packet -> get_tag())){
            signee_id = std::static_pointer_cast <Packet::User> (signee_packet);
        }
        else if (signee_packet -> get_tag() == Packet::SIGNATURE){
            // TODO differentiate between certification and revocation

            const Packet::Tag2::Ptr signee_signature = std::static_pointer_cast <Packet::Tag2> (signee_packet);

            // check if the signature is valid
            const int rc = primary_key(signer_key, signee_key, signee_id, signee_signature);
            if (rc == true){
                return true;
            }
            else if (rc == -1){
                // "Error: pka failure.\n";
                return -1;
            }
        }
    }

    return false;
}

// 0x18: Subkey Binding Signature

// 0x19: Primary Key Binding Signature

// 0x1F: Signature directly on a key

// 0x20: Key revocation signature
// 0x28: Subkey revocation signature
// 0x30: Certification revocation signature
int revoke(const Key & key, const RevocationCertificate & revoke){
    if (!key.meaningful()){
        // "Error: Bad PGP Key.\n";
        return -1;
    }

    if (!revoke.meaningful()){
        // "Error: A revocation key is required.\n";
        return -1;
    }

    // get revocation signature
    const Packet::Tag2::Ptr revoke_sig = std::static_pointer_cast <Packet::Tag2> (revoke.get_packets()[0]);

    // key IDs must match up
    const std::string keyid = key.keyid();
    if (keyid != revoke_sig -> get_keyid()){
        return false;
    }

    const Packet::Key::Ptr signing_key = find_signing_key(key);
    if (!signing_key){
        // "Error: No signing key found.\n";
        return -1;
    }

    // if the revocation signature is revoking the primary key
    if (revoke_sig -> get_type() == Signature_Type::KEY_REVOCATION_SIGNATURE){
        return with_pka(Hash::use(revoke_sig -> get_hash(), addtrailer(overkey(std::static_pointer_cast <Packet::Key> (key.get_packets()[0])), revoke_sig)), signing_key, revoke_sig);
    }
    else if (revoke_sig -> get_type() == Signature_Type::SUBKEY_REVOCATION_SIGNATURE){
        // search each packet for a subkey
        for(Packet::Tag::Ptr const & p : key.get_packets()){
            if (Packet::is_subkey(p -> get_tag())){
                const int rc = with_pka(to_sign_28(std::static_pointer_cast <Packet::Key> (p), revoke_sig), signing_key, revoke_sig);
                if (rc == true){
                    return true;
                }
                else if (rc == -1){
                    // "Error: pka failure.\n";
                    return -1;
                }
            }
        }

        return false;
    }
    else if (revoke_sig -> get_type() == Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE){
        for(Packet::Tag::Ptr const & p : key.get_packets()){
            if (Packet::is_user(p -> get_tag())){
                const Packet::User::Ptr user = std::static_pointer_cast <Packet::User> (p);
                const int rc = with_pka(to_sign_30(signing_key, user, revoke_sig), signing_key, revoke_sig);
                if (rc == true){
                    return true;
                }
                else if (rc == -1){
                    // "Error: pka failure.\n";
                    return -1;
                }
            }
        }

        return false;
    }

    // "Error: Bad revocation signature type.\n";
    return -1;
}

// 0x40: Timestamp signature.
int timestamp(const Key & key, const DetachedSignature & timestamp){
    if (!key.meaningful()){
        // "Error: Bad PGP Key.\n";
        return -1;
    }

    if (!timestamp.meaningful()){
        // "Error: Bad timestamp signature.\n";
        return -1;
    }

    const Packet::Tag2::Ptr signature = std::static_pointer_cast <Packet::Tag2> (timestamp.get_packets()[0]);

    // find key id in signature
    const std::string keyid = signature -> get_keyid();
    if (!keyid.size()){
        // "Error: No Key ID subpacket found.\n";
        return -1;
    }

    // make sure the key ID on the signature matches the Key's ID
    if (key.keyid() != keyid){
        return false;
    }

    // calculate the digest of the data (treated as binary)
    // and check the left 16 bits
    const std::string digest = to_sign_40(signature);
    if (digest.substr(0, 2) != signature -> get_left16()){
        // "Hash digest and given left 16 bits of hash do not match.\n";
        return false;
    }

    // get signing key
    const Packet::Key::Ptr signing_key = find_signing_key(key);
    if (!signing_key){
        // "Error: No public signing keys found.\n";
        return -1;
    }

    return with_pka(digest, signing_key, signature);
}

// 0x50: Third-Party Confirmation signature.

}
}
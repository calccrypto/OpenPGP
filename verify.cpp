#include "verify.h"

int pka_verify(const std::string & digest, const uint8_t hash, const uint8_t pka, const PKA::Values & signer, const PKA::Values & signee, std::string & error){
    if ((pka == PKA::RSA_ENCRYPT_OR_SIGN) ||
        (pka == PKA::RSA_SIGN_ONLY)){
        // RFC 4880 sec 5.2.2
        // If RSA, hash value is encoded using EMSA-PKCS1-v1_5
        return RSA_verify(EMSA_PKCS1_v1_5(hash, digest, bitsize(signer[0]) >> 3), signee, signer);
    }
    else if (pka == PKA::DSA){
        return DSA_verify(digest, signee, signer);
    }

    error += "Error: Bad PKA value.\n";
    return -1;
}

int pka_verify(const std::string & digest, const Key::Ptr & signer, const Tag2::Ptr & signee, std::string & error){
    return pka_verify(digest, signee -> get_hash(), signee -> get_pka(), signer -> get_mpi(), signee -> get_mpi(), error);
}

int verify_detached_signature(const PGPKey & key, const std::string & data, const PGPDetachedSignature & sig, std::string & error){
    if (!key.meaningful(error)){
        error += "Error: Bad PGP Key.\n";
        return -1;
    }

    if (!sig.meaningful(error)){
        error += "Error: Bad detached signature.\n";
        return -1;
    }

    const Tag2::Ptr signature = std::static_pointer_cast <Tag2> (sig.get_packets()[0]);

    // find key id in signature
    const std::string keyid = signature -> get_keyid();
    if (!keyid.size()){
        error += "Error: No Key ID subpacket found.\n";
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
        error += "Hash digest and given left 16 bits of hash do not match.\n";
        return false;
    }

    // get signing key
    const Key::Ptr signing_key = find_signing_key(key);
    if (!signing_key){
        error += "Error: No public signing keys found.\n";
        return -1;
    }

    return pka_verify(digest, signing_key, signature, error);
}

int verify_detached_signature(const PGPKey & key, const std::string & data, const PGPDetachedSignature & sig){
    std::string error;
    return verify_detached_signature(key, data, sig, error);
}

// 0x00: Signature of a binary document.
int verify_message(const PGPKey & key, const PGPMessage & message, std::string & error){
    if (!key.meaningful(error)){
        error += "Error: Bad PGP Key.\n";
        return -1;
    }

    if (!message.meaningful(error)){
        error += "Error: Bad message.\n";
        return -1;
    }

    // most of the time OpenPGP Message data is compressed
    // then it is encrypted

    if (message.match(PGPMessage::ENCRYPTEDMESSAGE, error)){
        // Encrypted Message :- Encrypted Data | ESK Sequence, Encrypted Data.
        error += "Error: Use decrypt to verify message.\n";
        return -1;
    }
    else if (message.match(PGPMessage::SIGNEDMESSAGE, error)){
        // Signed Message :- Signature Packet, OpenPGP Message | One-Pass Signed Message.
        // One-Pass Signed Message :- One-Pass Signature Packet, OpenPGP Message, Corresponding Signature Packet.

        // parse packets
        PGP::Packets packets = message.get_packets();

        //   Note that if a message contains more than one one-pass signature,
        //   then the Signature packets bracket the message; that is, the first
        //   Signature packet after the message corresponds to the last one-pass
        //   packet and the final Signature packet corresponds to the first
        //   one-pass packet.

        // Tag4_0, Tag4_1, ... , Tag4_n, Tag8/11, Tag2_n, ... , Tag2_1, Tag2_0

        unsigned int i = 0;
        std::list <Tag4::Ptr> OPSP;                                         // treat as stack
        while ((i < packets.size()) && (packets[i] -> get_tag() == Packet::ONE_PASS_SIGNATURE)){
            OPSP.push_front(std::static_pointer_cast <Tag4> (packets[i]));  // put next Tag4 onto stack
            i++;

            if ((*(OPSP.rbegin())) -> get_nested() != 0){                   // check if there are nested packets
                break;                                                      // just in case extra data was placed, allowing for errors later
            }
        }

        // get signed data
        std::string binary = packets[i] -> raw();
        i++;
        binary = Tag11(binary).get_literal();                               // binary data hashed directly
        std::string text;                                                   // text data line endings converted to <CR><LF>

        // cache text version of data
        // probably only one of binary or text is needed at one time
        if (binary[0] == '\n'){
            text = "\r";
        }
        text += std::string(1, binary[0]);
        unsigned int c = 1;
        while (c < binary.size()){
            if (binary[c] == '\n'){                                         // if current character is newline
                if (binary[c - 1] != '\r'){                                 // if previous character was not carriage return
                    text += "\r";                                           // add a carriage return
                }
            }
            text += std::string(1, binary[c++]);                            // add current character
        }

        // get signatures
        std::list <Tag2::Ptr> SP;                                           // treat as queue
        while ((i < packets.size()) && (packets[i] -> get_tag() == 2)){
            SP.push_front(std::static_pointer_cast <Tag2> (packets[i]));    // put next Tag2 onto queue
            i++;
        }

        // check for signatures
        if (!OPSP.size() || !SP.size()){
            error += "Error: No signature found.\n";
            return -1;

        }

        // both lists should be the same size
        if (OPSP.size() != SP.size()){
            error += "Error: Different number of One-Pass Signatures and Signature packets.\n";
            return -1;
        }

        // get signing key
        const Key::Ptr signing_key = find_signing_key(key);
        if (!signing_key){
            error += "Error: No public signing keys found.\n";
            return -1;
        }

        // check for matching signature
        bool verify = false;
        while (OPSP.size() && SP.size()){

            // // extra warnings
            // // check that KeyIDs match
            // if ((*(OPSP.rbegin())) -> get_keyid() == (*(SP.begin())) -> get_keyid()){

                // // check that all the parameters match
                // bool match = true;

                // // Signature Type
                // if ((*(OPSP.rbegin())) -> get_type() != (*(SP.begin())) -> get_type()){
                    // match = false;
                    // std::cerr << "Warning: One-Pass Signature Packet and Signature Packet Signature Type mismatch" << std::endl;
                // }

                // // Hash Algorithm
                // if ((*(OPSP.rbegin())) -> get_hash() != (*(SP.begin())) -> get_hash()){
                    // match = false;
                    // std::cerr << "Warning: One-Pass Signature Packet and Signature Packet Hash Algorithm mismatch" << std::endl;
                // }

                // // Public Key Algorithm
                // if ((*(OPSP.rbegin())) -> get_pka() != (*(SP.begin())) -> get_pka()){
                    // match = false;
                    // std::cerr << "Warning: One-Pass Signature Packet and Signature Packet Public Key Algorithm mismatch" << std::endl;
                // }

                // // check signature
                // if (match){

                    // if KeyID of given key matches this Tag4/Tag2 pair's KeyID
                    if (signing_key -> get_keyid() == (*(SP.begin())) -> get_keyid()){

                        // get hashed data
                        std::string digest;
                        if ((*(OPSP.rbegin())) -> get_type() == Signature_Type::SIGNATURE_OF_A_BINARY_DOCUMENT){
                            digest = to_sign_00(binary, *(SP.begin()));
                        }
                        else if ((*(OPSP.rbegin())) -> get_type() == Signature_Type::SIGNATURE_OF_A_CANONICAL_TEXT_DOCUMENT){
                                digest = to_sign_01(text, *(SP.begin()));
                        }

                        // don't know if other signature types can be here
                        // else if (Signature_Type::is_cert((*(OPSP.rbegin())) -> get_type())){
                            // std::cerr << "Warning: Bad signature type: " << std::to_string((*(OPSP.rbegin())) -> get_type()) << std::endl;
                            // verify = false;
                        // }
                        else{
                            std::cerr << "Warning: Bad signature type: " << std::to_string((*(OPSP.rbegin())) -> get_type()) << std::endl;
                            verify = false;
                            break;
                        }

                        if (verify){
                            // check if the key matches this signature
                            verify = pka_verify(digest, signing_key, *(SP.begin()), error);
                        }
                    }
                // }
            // }
            // else{
                // verify = false;
                // std:cerr << "Warning: One-Pass Signature Packet and Signature Packet KeyID mismatch" << std::endl;
            // }

            // free shared_ptr
            OPSP.rbegin() -> reset();
            SP.begin() -> reset();

            OPSP.pop_back(); // pop top of stack
            SP.pop_front();  // pop front of queue
        }

        return verify;
    }
    else if (message.match(PGPMessage::COMPRESSEDMESSAGE, error)){
        // Compressed Message :- Compressed Data Packet.

        // decompress data
        // assume only one compressed data packet
        return verify_message(key, PGPMessage(std::static_pointer_cast <Tag8> (message.get_packets()[0]) -> get_data()), error);
    }
    else if (message.match(PGPMessage::LITERALMESSAGE, error)){
        // Literal Message :- Literal Data Packet.

        // only one literal data packet
        std::string compressed = message.get_packets()[0] -> raw();

        // extract data
        Tag11 tag11(compressed);
        compressed = tag11.get_literal(); // not sure if this is correct

        return verify_message(key, PGPMessage(compressed), error);
    }

    error += "Error: Not an OpenPGP Message. Perhaps Detached Signature?\n";
    return -1;
}

int verify_message(const PGPKey & key, const PGPMessage & message){
    std::string error;
    return verify_message(key, message, error);
}

// Signature type 0x01
int verify_cleartext_signature(const PGPKey & key, const PGPCleartextSignature & message, std::string & error){
    if (!key.meaningful(error)){
        error += "Error: Bad PGP Key.\n";
        return -1;
    }

    if (!message.meaningful(error)){
        error += "Error: A Cleartext Signature is needed.\n";
        return -1;
    }

    // find key id from signature to match with public key
    Tag2::Ptr signature = std::static_pointer_cast <Tag2> (message.get_sig().get_packets()[0]);
    if (!signature){
        error += "Error: No signature found.\n";
        return -1;
    }

    // find key id in signature
    std::string keyid = signature -> get_keyid();
    if (!keyid.size()){
        error += "Error: No Key ID subpacket found.\n";
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
        error += "Hash digest and given left 16 bits of hash do not match.\n";
        return -1;
    }

    // get signing key
    const Key::Ptr signing_key = find_signing_key(key);
    if (!signing_key){
        error += "Error: No public signing keys found.\n";
        return -1;
    }

    return pka_verify(digest, signing_key, signature, error);
}

int verify_cleartext_signature(const PGPKey & key, const PGPCleartextSignature & message){
    std::string error;
    return verify_cleartext_signature(key, message, error);
}

// 0x02: Standalone signature.

// 0x10: Generic certification of a User ID and Public-Key packet.
// 0x11: Persona certification of a User ID and Public-Key packet.
// 0x12: Casual certification of a User ID and Public-Key packet.
// 0x13: Positive certification of a User ID and Public-Key packet.
int verify_key(const Key::Ptr & signer_key, const Key::Ptr & signee_key, const User::Ptr & signee_id, const Tag2::Ptr & signee_signature, std::string & error){
    // if the signing key's ID doesn't match with the signature's ID
    if ((signer_key -> get_keyid() != signee_signature -> get_keyid())){
        return false;
    }

    // check if the signature is valid
    return pka_verify(to_sign_cert(signee_signature -> get_type(), signee_key, signee_id, signee_signature), signer_key, signee_signature, error);
}

int verify_key(const PGPKey & signer, const PGPKey & signee, std::string & error){
    if (!signer.meaningful(error)){
        error += "Error: Bad Signer Key.\n";
        return -1;
    }

    if (!signee.meaningful(error)){
        error += "Error: Bad Signee Key.\n";
        return -1;
    }

    // get signer's key id
    const std::string signer_keyid = signer.keyid();
    if (!signer_keyid.size()){
        error += "Error: Signer key does not have a key id.\n";
        return -1;
    }

    // get signing key
    const Key::Ptr signer_key = find_signing_key(signer);
    if (!signer_key){
        error += "Error: No signing keys found.\n";
        return -1;
    }

    // keep track of Key and UID being verified
    Key::Ptr signee_key = nullptr;
    User::Ptr signee_id = nullptr;

    // for each signature packet on the signee
    for(Packet::Ptr const & signee_packet : signee.get_packets()){
        if (Packet::is_primary_key(signee_packet -> get_tag())){
            signee_key = std::static_pointer_cast <Key> (signee_packet);
            signee_id = nullptr;        // need to find new User information
        }
        else if (Packet::is_user(signee_packet -> get_tag())){
            signee_id = std::static_pointer_cast <User> (signee_packet);
        }
        else if (signee_packet -> get_tag() == Packet::SIGNATURE){
            // TODO differentiate between certification and revocation

            const Tag2::Ptr signee_signature = std::static_pointer_cast <Tag2> (signee_packet);

            // check if the signature is valid
            const int rc = verify_key(signer_key, signee_key, signee_id, signee_signature, error);
            if (rc == 1){
                return true;
            }
            else if (rc == -1){
                error += "Error: pka_verify failure.\n";
                return -1;
            }
        }
    }

    return false;
}

int verify_key(const PGPKey & signer, const PGPKey & signee){
    std::string error;
    return verify_key(signer, signee, error);
}

// 0x18: Subkey Binding Signature

// 0x19: Primary Key Binding Signature

// 0x1F: Signature directly on a key

// 0x20: Key revocation signature
// 0x28: Subkey revocation signature
// 0x30: Certification revocation signature
int verify_revoke(const PGPKey & key, const PGPRevocationCertificate & revoke, std::string & error){
    if (!key.meaningful(error)){
        error += "Error: Bad PGP Key.\n";
        return -1;
    }

    if (!revoke.meaningful(error)){
        error += "Error: A revocation key is required.\n";
        return -1;
    }

    // get revocation signature
    const Tag2::Ptr revoke_sig = std::static_pointer_cast <Tag2> (revoke.get_packets()[0]);

    // key IDs must match up
    const std::string keyid = key.keyid();
    if (keyid != revoke_sig -> get_keyid()){
        return false;
    }

    Key::Ptr signing_key = find_signing_key(key);
    if (!signing_key){
        error += "Error: No signing key found.\n";
        return -1;
    }

    // if the revocation signature is revoking the primary key
    if (revoke_sig -> get_type() == Signature_Type::KEY_REVOCATION_SIGNATURE){
        return pka_verify(use_hash(revoke_sig -> get_hash(), addtrailer(overkey(std::static_pointer_cast <Key> (key.get_packets()[0])), revoke_sig)), signing_key, revoke_sig, error);
    }
    else if (revoke_sig -> get_type() == Signature_Type::SUBKEY_REVOCATION_SIGNATURE){
        // search each packet for a subkey
        for(Packet::Ptr const & p : key.get_packets()){
            if (Packet::is_subkey(p -> get_tag())){
                const int rc = pka_verify(use_hash(revoke_sig -> get_hash(), addtrailer(overkey(std::static_pointer_cast <Key> (p)), revoke_sig)), signing_key, revoke_sig, error);
                if (rc == 1){
                    return true;
                }
                else if (rc == -1){
                    error += "Error: pka_verify failure.\n";
                    return -1;
                }
            }
        }

        return false;
    }

    error += "Error: Bad revocation signature type.\n";
    return -1;
}

int verify_revoke(const PGPKey & key, const PGPRevocationCertificate & revoke){
    std::string error;
    return verify_revoke(key, revoke, error);
}

// 0x40: Timestamp signature.

// 0x50: Third-Party Confirmation signature.

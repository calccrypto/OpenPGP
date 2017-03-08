#include "verify.h"

int pka_verify(const std::string & digest, const uint8_t hash, const uint8_t pka, const PKA::Values & signer, const PKA::Values & signee){
    if ((pka == PKA::RSA_ENCRYPT_OR_SIGN) ||
        (pka == PKA::RSA_SIGN_ONLY)){
        // RFC 4880 sec 5.2.2
        // If RSA, hash value is encoded using EMSA-PKCS1-v1_5
        return RSA_verify(EMSA_PKCS1_v1_5(hash, digest, bitsize(signer[0]) >> 3), signee, signer);
    }
    else if (pka == PKA::DSA){
        return DSA_verify(digest, signee, signer);
    }
    return -1;
}

int pka_verify(const std::string & digest, const Key::Ptr & signer, const Tag2::Ptr & signee){
    return pka_verify(digest, signee -> get_hash(), signee -> get_pka(), signer -> get_mpi(), signee -> get_mpi());
}

int verify_detached_signature(const PGPKey & key, const std::string & data, const PGPDetachedSignature & sig, std::string & error){
    if (!sig.meaningful(error)){
        error += "Error: A Detached Signature is required.\n";
        return -1;
    }

    if (!key.meaningful(error)){
        error += "Error: Bad PGP Key.\n";
        return -1;
    }

    Tag2::Ptr signature = std::static_pointer_cast <Tag2> (sig.get_packets()[0]);

    // find key id in signature
    std::string keyid = signature -> get_keyid();
    if (!keyid.size()){
        error += "Error: No Key ID subpacket found.\n";
        return -1;
    }

    // calculate the digest of the data (treated as binary)
    // and check the left 16 bits
    std::string digest = to_sign_00(binary_to_canonical(data), signature);
    if (digest.substr(0, 2) != signature -> get_left16()){
        error += "Hash digest and given left 16 bits of hash do not match.\n";
        return false;
    }

    // search each packet for a signing key
    for(Packet::Ptr const & p : key.get_packets()){

        // check if the packet is a key packet
        if (Packet::is_key_packet(p -> get_tag())){
            Key::Ptr kp = std::static_pointer_cast <Key> (p);

            // make sure the key's  values can be used to sign
            if (PKA::can_sign(kp -> get_pka())){

                if (pka_verify(digest, kp, signature) == 1){
                    // make sure key IDs match up
                    if (kp -> get_keyid() != signature -> get_keyid()){
                        error += "Warning: Key IDs don't match up.\n";
                    }

                    return 1;
                }
            }
        }
    }

    return false;
}

int verify_detached_signature(const PGPKey & key, const std::string & data, const PGPDetachedSignature & sig){
    std::string error;
    return verify_detached_signature(key, data, sig, error);
}

// 0x00: Signature of a binary document.
int verify_message(const Key::Ptr & signing_key, const PGPMessage & m, std::string & error){
    if (!signing_key){
        error += "Error: Bad signing key.\n";
        return -1;
    }

    if (!m.meaningful(error)){
        error += "Error: Bad message.\n";
        return -1;
    }

    // most of the time OpenPGP Message data is compressed
    // then it is encrypted

    if (m.match(PGPMessage::ENCRYPTEDMESSAGE, error)){
        // Encrypted Message :- Encrypted Data | ESK Sequence, Encrypted Data.
        error += "Error: Use decrypt to verify message.\n";
        return -1;
    }
    else if (m.match(PGPMessage::SIGNEDMESSAGE, error)){
        // Signed Message :- Signature Packet, OpenPGP Message | One-Pass Signed Message.
        // One-Pass Signed Message :- One-Pass Signature Packet, OpenPGP Message, Corresponding Signature Packet.

        // parse packets
        PGP::Packets packets = m.get_packets();

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
                            verify = pka_verify(digest, signing_key, *(SP.begin()));
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
    else if (m.match(PGPMessage::COMPRESSEDMESSAGE, error)){
        // Compressed Message :- Compressed Data Packet.

        // only one compressed data packet
        std::string message = m.get_packets()[0] -> raw();

        // decompress data
        Tag8 tag8(message);
        message = tag8.get_data();

        return verify_message(signing_key, PGPMessage(message), error);
    }
    else if (m.match(PGPMessage::LITERALMESSAGE, error)){
        // Literal Message :- Literal Data Packet.

        // only one literal data packet
        std::string message = m.get_packets()[0] -> raw();

        // extract data
        Tag11 tag11(message);
        message = tag11.get_literal(); // not sure if this is correct

        return verify_message(signing_key, PGPMessage(message), error);
    }

    error += "Error: Not an OpenPGP Message. Perhaps Detached Signature?\n";
    return -1;
}

int verify_message(const PGPKey & key, const PGPMessage & message, std::string & error){
    if (!key.meaningful(error)){
        error += "Error: Bad PGP Key.\n";
        return -1;
    }

    // get signing key
    Tag6::Ptr signing_key = nullptr;
    for(Packet::Ptr const & p : key.get_packets()){
        // if its a public key packet
        if ((p -> get_tag() == Packet::PUBLIC_KEY) || (p -> get_tag() == Packet::PUBLIC_SUBKEY)){
            Tag6::Ptr tag6 = std::static_pointer_cast <Tag6> (p);

            // if its a signing key packet
            if (PKA::can_sign(tag6 -> get_pka())){
                // get keys
                signing_key = tag6;
                break;
            }
        }
    }

    if (!signing_key){
        error += "Error: No public signing keys found\n";
        return -1;
    }

    return verify_message(signing_key, message, error);
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

    // calculate the digest of the cleartext data (trailing whitespace removed)
    // and check the left 16 bits
    const std::string digest = to_sign_01(message.data_to_text(), signature);
    if (digest.substr(0, 2) != signature -> get_left16()){
        error += "Hash digest and given left 16 bits of hash do not match.\n";
        return -1;
    }

    // search each packet for a signing key
    for(Packet::Ptr const & p : key.get_packets()){

        // check if the packet is a key packet
        if (Packet::is_key_packet(p -> get_tag())){
            Key::Ptr kp = std::static_pointer_cast <Key> (p);

            // make sure the key's  values can be used to sign
            if (PKA::can_sign(kp -> get_pka())){

                if (pka_verify(digest, kp, signature) == 1){
                    // make sure key IDs match up
                    if (kp -> get_keyid() != signature -> get_keyid()){
                        error += "Warning: Key IDs don't match up.\n";
                    }

                    return 1;
                }
            }
        }
    }

    return false;
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
int verify_key(const PGPKey & signer, const PGPKey & signee, std::string & error){
    if (!signer.meaningful(error)){
        error += "Error: Bad PGP Key.\n";
        return -1;
    }

    if (!signee.meaningful(error)){
        error += "Error: Bad PGP Key.\n";
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

            const uint8_t signee_key_version = signee_key -> get_version();
            const std::string signee_key_str = overkey(signee_key);
            const std::string signee_user_str = certification(signee_key_version, signee_id);

            const Tag2::Ptr signee_signature = std::static_pointer_cast <Tag2> (signee_packet);

            // add hash contexts together and append trailer data
            const std::string signee_with_trailer = addtrailer(signee_key_str + signee_user_str, signee_signature);
            const std::string hash = use_hash(signee_signature -> get_hash(), signee_with_trailer);

            // search through signer for signing keys
            for(Packet::Ptr const & signer_packet : signer.get_packets()){
                if (Packet::is_key_packet(signer_packet -> get_tag())){
                    const Key::Ptr signer_key = std::static_pointer_cast <Key> (signer_packet);
                    // if the signing key's ID matches with the signature's ID
                    if ((signer_key -> get_keyid() == signee_signature -> get_keyid())){
                        // check if the signature is valid
                        if (pka_verify(hash, signer_key, signee_signature)){
                            return true;
                        }
                    }
                }
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
int verify_revoke(const PGPKey & key, const PGPPublicKey & rev, std::string & error){
    if (!key.meaningful(error)){
        error += "Error: Bad PGP Key.\n";
        return -1;
    }

    if (!rev.meaningful(error)){
        error += "Error: A revocation key is required.\n";
        return -1;
    }

    if (rev.get_packets().size() != 1){
        error += "Error: Wrong number of packets in revocation certificate.\n";
        return -1;
    }

    if (rev.get_packets()[0] -> get_tag() != Packet::SIGNATURE){
        error += "Error: Revocation certificate should contain one " + Packet::NAME.at(Packet::SIGNATURE) + ".\n";
        return -1;
    }

   // get revocation key; assume only 1 packet
    Tag2::Ptr revoke = std::static_pointer_cast <Tag2> (rev.get_packets()[0]);

    // search each packet for a signing key
    for(Packet::Ptr const & p : key.get_packets()){
        // check if the packet is a key packet
        if (Packet::is_key_packet(p -> get_tag())){
            Key::Ptr kp = std::static_pointer_cast <Key> (p);

            // make sure the key's  values can be used to sign
            if (PKA::can_sign(kp -> get_pka())){

                if (pka_verify(use_hash(revoke -> get_hash(), addtrailer(overkey(kp), revoke)), kp, revoke) == 1){
                    // make sure key IDs match up
                    if (kp -> get_keyid() != revoke -> get_keyid()){
                        error += "Warning: Key IDs don't match up.\n";
                    }

                    return 1;
                }
            }
        }
    }

    return false;
}

int verify_revoke(const PGPKey & pub, const PGPPublicKey & rev){
    std::string error;
    return verify_revoke(pub, rev, error);
}

// 0x40: Timestamp signature.

// 0x50: Third-Party Confirmation signature.

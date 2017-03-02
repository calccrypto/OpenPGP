#include "verify.h"

bool pka_verify(const std::string & digest, const uint8_t hash, const uint8_t pka, const std::vector <PGPMPI> & signing, const std::vector<PGPMPI> & signature){
    if ((pka == 1) || (pka == 3)){ // RSA
        std::string encoded = EMSA_PKCS1_v1_5(hash, digest, bitsize(signing[0]) >> 3);
        return RSA_verify(encoded, signature, signing);
    }
    else if (pka == 17){           // DSA
        return DSA_verify(digest, signature, signing);
    }
    return false;
}

bool pka_verify(const std::string & digest, const Tag6::Ptr signing, const Tag2::Ptr & signature){
    return pka_verify(digest, signature -> get_hash(), signature -> get_pka(), signing -> get_mpi(), signature -> get_mpi());
}

// Signature type 0x00 and 0x01
bool verify_cleartext_signature(const PGPPublicKey & pub, const PGPCleartextSignature & message, std::string * error){
    if (error){
        error -> clear();
    }

    if ((pub.get_ASCII_Armor() != 1) && (pub.get_ASCII_Armor() != 2)){
        throw std::runtime_error("Error: A PGP key is required.");
    }

    // Find key id from signature to match with public key
    std::string temp = message.get_sig().get_packets()[0] -> raw();
    Tag2::Ptr signature = std::make_shared <Tag2> (); signature -> read(temp);

    // check left 16 bits
    std::string digest = to_sign_01(message.get_canonical_message(), signature);
    if (digest.substr(0, 2) != signature -> get_left16()){
        if (error){
            *error = "Error: Hash digest and given left 16 bits of hash do not match.";
        }
        return false;
    }

    // find key id in signature
    std::string keyid = signature -> get_keyid();
    if (!keyid.size()){
        throw std::runtime_error("Error: No Key ID subpacket found.");
    }

    // find matching public key packet and get the mpi
    Tag6::Ptr signingkey = find_signing_key(pub, 6, keyid); // search for primary key

    if (!signingkey){                                       // if no signing primary key
        signingkey = find_signing_key(pub, 14, keyid);      // search for subkey
    }

    if (!signingkey){
        throw std::runtime_error("Error: No signing key found.");
    }

    bool verify = pka_verify(digest, signingkey, signature);

    if (error){
        *error = verify?std::string("Success"):std::string("PKA calculations dont match.");
    }

    return verify;
}

bool verify_cleartext_signature(const PGPSecretKey & pri, const PGPCleartextSignature & message, std::string * error){
    return verify_cleartext_signature(PGPPublicKey(pri), message, error);
}

bool verify_detachedsig(const PGPPublicKey & pub, const std::string & data, const PGPDetachedSignature & sig, std::string * error){
    if (error){
        error -> clear();
    }

    if (sig.get_ASCII_Armor() != 5){
        throw std::runtime_error("Error: A signature packet is required.");
    }

    if ((pub.get_ASCII_Armor() != 1) && (pub.get_ASCII_Armor() != 2)){
        throw std::runtime_error("Error: A PGP key is required.");
    }

    std::string temp = sig.get_packets()[0] -> raw();
    Tag2::Ptr signature = std::make_shared <Tag2> (temp);

    // Check left 16 bits
    std::string digest = to_sign_00(data, signature);
    if (digest.substr(0, 2) != signature -> get_left16()){
        if (error){
            *error = "Hash digest and given left 16 bits of hash do not match.";
        }
        return false;
    }

    // find key id in signature
    std::string keyid = signature -> get_keyid();
    if (!keyid.size()){
        throw std::runtime_error("Error: No Key ID subpacket found.");
    }

    // find matching public key packet and get the mpi
    Tag6::Ptr signingkey = find_signing_key(pub, 6, keyid);
    if (!signingkey){                                        // if no signing primary key
        signingkey = find_signing_key(pub, 14, keyid);       // search for subkey
    }

    if (!signingkey){
        throw std::runtime_error("Error: No signing found.");
    }

    bool verify = pka_verify(digest, signingkey, signature);

    if (error){
        *error = verify?std::string("Success"):std::string("PKA calculations dont match.");
    }

    return verify;
}

bool verify_detachedsig(const PGPSecretKey & pri, const std::string & data, const PGPDetachedSignature & sig, std::string * error){
    return verify_detachedsig(PGPPublicKey(pri), data, sig, error);
}

bool verify_detachedsig(const PGPPublicKey & pub, std::istream & stream, const PGPDetachedSignature & sig, std::string * error){
    if (error){
        error -> clear();
    }

    if (!stream){
        throw std::runtime_error("Error: Bad stream.");
    }
    std::stringstream s;
    s << stream.rdbuf();
    std::string data = s.str();

    return verify_detachedsig(pub, data, sig, error);
}

bool verify_detachedsig(const PGPSecretKey & pri, std::istream & stream, const PGPDetachedSignature & sig, std::string * error){
    return verify_detachedsig(PGPPublicKey(pri), stream, sig);
}

bool verify_message(const Tag6::Ptr & signing_key, const PGPMessage & m, std::string * error){
    // most of the time OpenPGP Message data is compressed
    // then it is encrypted

    if (error){
        error -> clear();
    }

    if (m.match(PGPMessage::ENCRYPTEDMESSAGE)){
        // Encrypted Message :- Encrypted Data | ESK Sequence, Encrypted Data.
        throw std::runtime_error("Error: Use decrypt to verify message.");
    }
    else if (m.match(PGPMessage::SIGNEDMESSAGE)){
        // // Signed Message :- Signature Packet, OpenPGP Message | One-Pass Signed Message.
        // // One-Pass Signed Message :- One-Pass Signature Packet, OpenPGP Message, Corresponding Signature Packet.

        // parse packets
        std::vector <Packet::Ptr> packets = m.get_packets();

        /*
        Note that if a message contains more than one one-pass signature,
        then the Signature packets bracket the message; that is, the first
        Signature packet after the message corresponds to the last one-pass
        packet and the final Signature packet corresponds to the first
        one-pass packet.
        */

        // Tag4_0, Tag4_1, ... , Tag4_n, Tag8/11, Tag2_n, ... , Tag2_1, Tag2_0

        unsigned int i = 0;
        std::list <Tag4::Ptr> OPSP;                                         // treat as stack
        while ((i < packets.size()) && (packets[i] -> get_tag() == 4)){
            OPSP.push_front(std::make_shared <Tag4> (packets[i] -> raw())); // put next Tag4 onto stack
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
            SP.push_front(std::make_shared <Tag2> (packets[i] -> raw()));   // put next Tag2 onto queue
            i++;
        }

        // check for signatures
        if (!OPSP.size() || !SP.size()){
            throw std::runtime_error("Error: No signature found.");
        }

        // both lists should be the same size
        if (OPSP.size() != SP.size()){
            throw std::runtime_error("Error: Different number of One-Pass Signatures and Signature packets.");
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
                        switch ((*(OPSP.rbegin())) -> get_type()){
                            case 0:
                                digest = to_sign_00(binary, *(SP.begin()));
                                break;
                            case 1:
                                digest = to_sign_01(text, *(SP.begin()));
                                break;

                            // don't know if other signature types can be here

                            // certifications
                            case 0x10: case 0x11:
                            case 0x12: case 0x13:
                            default:
                                {
                                    std::cerr << "Warning: Bad signature type: " << static_cast <unsigned int> ((*(OPSP.rbegin())) -> get_type()) << std::endl;
                                    verify = false;
                                }
                                break;
                        }

                        // check if the key matches this signature
                        verify = pka_verify(digest, signing_key, *(SP.begin()));
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

        if (error){
            *error = verify?std::string("Success"):std::string("Failure");
        }

        return verify;
    }
    else if (m.match(PGPMessage::COMPRESSEDMESSAGE)){
        // Compressed Message :- Compressed Data Packet.

        // only one compressed data packet
        std::string message = m.get_packets()[0] -> raw();

        // decompress data
        Tag8 tag8(message);
        message = tag8.get_data();

        return verify_message(signing_key, PGPMessage(message), error);
    }
    else if (m.match(PGPMessage::LITERALMESSAGE)){
        // Literal Message :- Literal Data Packet.

        // only one literal data packet
        std::string message = m.get_packets()[0] -> raw();

        // extract data
        Tag11 tag11(message);
        message = tag11.get_literal(); // not sure if this is correct

        return verify_message(signing_key, PGPMessage(message), error);
    }
    else{
        throw std::runtime_error("Error: Not an OpenPGP Message. Perhaps Detached Signature?");
    }

    if (error){
        *error = "Failure";
    }

    return false; // get rid of compiler warnings
}

bool verify_message(const PGPPublicKey & pub, const PGPMessage & m, std::string * error){
    if (error){
        error -> clear();
    }

    // get signing key
    Tag6::Ptr signing_key = nullptr;
    for(Packet::Ptr const & p : pub.get_packets()){
        // if its a public key packet
        if ((p -> get_tag() == 6) || (p -> get_tag() == 14)){
            Tag6::Ptr tag6 = std::make_shared <Tag6> (p -> raw());

            // if its a signing key packet
            if ((tag6 -> get_pka() == 1) || (tag6 -> get_pka() == 3) || (tag6 -> get_pka() == 17)){
                // get keys
                signing_key = tag6;
                break;
            }
        }
    }

    if (!signing_key){
        throw std::runtime_error("Error: No public signing keys found");
    }

    const bool verify = verify_message(signing_key, m, error);

    if (error){
        *error = verify?std::string("Success"):std::string("Message verification failed.");
    }

    return verify;
}

bool verify_message(const PGPSecretKey & pri, const PGPMessage & m, std::string * error){
    return verify_message(PGPPublicKey(pri), m, error);
}

// Signature Type 0x10 - 0x13
bool verify_key(const PGPPublicKey & signer, const PGPPublicKey & signee, std::string * error){
    if ((signer.get_ASCII_Armor() != 1) && (signer.get_ASCII_Armor() != 2)){
        throw std::runtime_error("Error: A PGP key is required.");
    }

    if ((signee.get_ASCII_Armor() != 1) && (signee.get_ASCII_Armor() != 2)){
        throw std::runtime_error("Error: A PGP key is required.");
    }

    // get Key ID of signer
    std::string keyid;
    // find signature packet on signer
    for(Packet::Ptr const & p : signer.get_packets()){
        if (p -> get_tag() == 2){
            std::string temp = p -> raw();
            Tag2::Ptr tag2 = std::make_shared <Tag2> (temp);
            // if this signature packet is a certification signature packet
            if ((0x10 <= tag2 -> get_type()) && (tag2 -> get_type() <= 0x13)){
                keyid = tag2 -> get_keyid();
                break;
            }
        }
    }

    if (!keyid.size()){
        throw std::runtime_error("Error: No signer Key ID packet found.");
    }

    // find signing key
    Tag6::Ptr signingkey = find_signing_key(signer, 6, keyid);
    if (!signingkey){                                                           // if no signing primary key
        signingkey = find_signing_key(signer, 14, keyid);                       // search for subkey
    }

    if (!signingkey){
        throw std::runtime_error("Error: No signing key found.");
    }

    uint8_t version = 0;
    std::string key_str = "";
    std::string user_str = "";

    // set packets to signatures to verify
    bool signaturefound = false;
    Tag6::Ptr tag6 = nullptr;
    for(Packet::Ptr const & p : signee.get_packets()){
        switch (p -> get_tag()){
            case 5: case 6: case 7: case 14:                                    // key packet
                tag6 = std::make_shared <Tag6> (p -> raw());
                key_str += overkey(tag6);                                       // add current key packet to previous ones
                version = tag6 -> get_version();
                tag6.reset();
                break;
            case 13: case 17:                                                   // User packet
                {
                    ID::Ptr id;
                    if (p -> get_tag() == 13){
                        id = std::make_shared <Tag13> ();
                    }
                    if (p -> get_tag() == 17){
                        id = std::make_shared <Tag17> ();
                    }
                    id -> read(p -> raw());
                    user_str = certification(version, id);                      // write over old user information
                }
                break;
            case 2:                                                             // signature packet
                {
                    // copy packet data into signature packet
                    Tag2::Ptr tag2 = std::make_shared <Tag2> (p -> raw());

                    // if signature is key binding, erase the user information
                    if ((tag2 -> get_type() == 0x18) ||
                        (tag2 -> get_type() == 0x19)){
                        user_str = "";
                    }

                    // add hash contexts together and append trailer data
                    const std::string with_trailer = addtrailer(key_str + user_str, tag2);
                    const std::string hash = use_hash(tag2 -> get_hash(), with_trailer);
                    if (hash.substr(0, 2) == tag2 -> get_left16()){             // quick signature check
                        signaturefound = pka_verify(hash, signingkey, tag2);    // proper signature check
                    }
                }
                break;
            default:
                {
                    std::stringstream s; s << static_cast <unsigned int> (p -> get_tag());
                    throw std::runtime_error("Error: Incorrect packet type found: " + s.str());
                }
                break;
        }

        if(signaturefound){
            break;
        }
    }

    return signaturefound;
}

bool verify_key(const PGPSecretKey & signer, const PGPPublicKey & signee, std::string * error){
    return verify_key(PGPPublicKey(signer), signee, error);
}

bool verify_revoke(const Tag6::Ptr & key, const Tag2::Ptr & rev){
    return pka_verify(use_hash(rev -> get_hash(), addtrailer(overkey(key), rev)), key, rev);
}

bool verify_revoke(const PGPPublicKey & pub, const PGPPublicKey & rev, std::string * error){
    if (error){
        error -> clear();
    }

    if ((pub.get_ASCII_Armor() != 1) && (pub.get_ASCII_Armor() != 2)){
        throw std::runtime_error("Error: A PGP key is required.");
    }

    if (rev.get_ASCII_Armor() != 1){
        throw std::runtime_error("Error: A revocation key is required.");
    }

    std::vector <Packet::Ptr> keys = pub.get_packets();

    // copy revocation signature into tag2
    std::vector <Packet::Ptr> rev_pointers = rev.get_packets();

    // get revocation key; assume only 1 packet
    std::string rev_str = rev_pointers[0] -> raw();
    Tag2::Ptr revoke = std::make_shared <Tag2> (rev_str);

    // for each key packet
    for(Packet::Ptr const & p : keys){
        // check if the packet is a key packet
        if ((p -> get_tag() == 5) ||
            (p -> get_tag() == 6) ||
            (p -> get_tag() == 7) ||
            (p -> get_tag() == 14)){

            // copy the key into Tag 6
            Tag6::Ptr tag6 = std::make_shared <Tag6> (p -> raw());

            // check if it was revoked
            if (verify_revoke(tag6, revoke)){
                return true;
            }
        }
    }

    if (error){
        *error = "PKA calculations dont match.";
    }

    return false;
}

bool verify_revoke(const PGPSecretKey & pri, const PGPPublicKey & rev, std::string * error){
    return verify_revoke(PGPPublicKey(pri), rev, error);
}

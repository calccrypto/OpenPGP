#include "decrypt.h"

Tag5::Ptr find_decrypting_key(const PGPSecretKey & k, const std::string & keyid){
    for(Packet::Ptr const & p : k.get_packets()){
        if (Packet::is_secret(p -> get_tag())){
            Tag5::Ptr key = std::static_pointer_cast <Tag5> (p);
            if (key -> get_public_ptr() -> get_keyid() != keyid ){
                continue;
            }

            // make sure key has encrypting keys
            if (PKA::can_encrypt(key -> get_pka())){
                return key;
            }
        }
    }
    return nullptr;
}

std::string pka_decrypt(const uint8_t pka,
                        const PKA::Values & data,
                        const PKA::Values & pri,
                        const PKA::Values & pub){
    if ((pka == PKA::RSA_ENCRYPT_OR_SIGN) ||
        (pka == PKA::RSA_ENCRYPT_ONLY)){
        return mpitoraw(RSA_decrypt(data[0], pri, pub));
    }
    else if (pka == PKA::ELGAMAL){
        return ElGamal_decrypt(data, pri, pub);
    }
    else{
        throw std::runtime_error("Error: PKA number " + std::to_string(pka) + " not allowed or unknown.");
    }
    return ""; // should never reach here; mainly just to remove compiler warnings
}

PGPMessage decrypt_data(const uint8_t sym,
                        const PGPMessage & message,
                        const std::string & session_key,
                        std::string & error){
    if (!message.meaningful(error)){
        error += "Error: Bad message.\n";
        return PGPMessage();
    }

    // find start of encrypted data
    PGP::Packets::size_type i = 0;
    PGP::Packets packets = message.get_packets();
    while ((i < packets.size()) && !Packet::is_sym_protected_data(packets[i] -> get_tag())){
        i++;
    }

    if (i == packets.size()){
        error += "Error: No encrypted data found.\n";
        return PGPMessage();
    }

    // current packet tag being operated on
    uint8_t tag;

    // Find encrypted data
    std::string data = "";

    // copy initial data to string
    if (packets[i] -> get_tag() == Packet::SYMMETRICALLY_ENCRYPTED_DATA){
        data = std::static_pointer_cast <Tag9> (packets[i]) -> get_encrypted_data();
        tag = Packet::SYMMETRICALLY_ENCRYPTED_DATA;
    }
    else if (packets[i] -> get_tag() == Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA){
        data = std::static_pointer_cast <Tag18> (packets[i]) -> get_protected_data();
        tag = Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA;
    }

    // does not work
    // // if the packet was a partial start
    // if (packets[i] -> get_partial()){
        // i++;

        // // add the rest of the data
        // for(; i < packets.size(); i++){
            // std::string raw = packets[i] -> raw();
            // Partial::Ptr part = std::make_shared <Partial> (raw);
            // data += part -> get_stream();

            // // if the current packet is parital end, break after adding data
            // if (packets[i] -> get_partial() == 3){
                // break;
            // }
        // }
    // }

    if (!data.size()){
        error += "Error: No encrypted data packet(s) found.\n";
        return PGPMessage();
    }

    // decrypt data
    data = use_OpenPGP_CFB_decrypt(sym, tag, data, session_key);

    // get blocksize of symmetric key algorithm
    const unsigned int BS = Sym::BLOCK_LENGTH.at(sym) >> 3;

    // strip extra data
    if (tag == Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA){
        const std::string checksum = data.substr(data.size() - 20, 20); // get given SHA1 checksum
        data = data.substr(0, data.size() - 20);                        // remove SHA1 checksum
        if (use_hash(Hash::SHA1, data) != checksum){                    // check SHA1 checksum
            error += "Error: Given checksum and calculated checksum do not match.";
            return PGPMessage();
        }

        data = data.substr(0, data.size() - 2);                         // get rid of \xd3\x14
    }

    data = data.substr(BS + 2, data.size() - BS - 2);                   // get rid of prefix

    // decompress and parse decrypted data
    return PGPMessage(data);
}

std::string decrypt_pka(const PGPSecretKey & pri,
                        const std::string & passphrase,
                        const PGPMessage & message,
                        const PGPKey::Ptr & signer,
                        int * verified,
                        std::string & error){
    if (!pri.meaningful(error)){
        error += "Error: Bad private key.\n";
        return "";
    }

    if (!message.meaningful(error)){
        error += "Error: No encrypted message found.\n";
        return "";
    }

    if (signer){
        if (!signer -> meaningful(error)){
            error += "Error: Bad signer key.\n";
            return "";
        }

        if (!verified){
            error += "Error: Need a bool when providing signer key.\n";
            return "";
        }
    }


    // find session key packet; should be first packet
    Tag1::Ptr tag1 = nullptr;
    for(Packet::Ptr const & p : message.get_packets()){
        if (p -> get_tag() == Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY){
            tag1 = std::static_pointer_cast <Tag1> (p);
            break;
        }
    }

    if (!tag1){
        error += "Error: No " + Packet::NAME.at(Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY) + " (Tag " + std::to_string(Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY) + ") found.\n";
        return "";
    }

    // Public-Key Encrypted Session Key Packet (Tag 1)
    const uint8_t pka = tag1 -> get_pka();
    PKA::Values session_key_mpi = tag1 -> get_mpi();

    // find corresponding secret key
    const Tag5::Ptr sec = find_decrypting_key(pri, tag1 -> get_keyid());
    if (!sec){
        error += "Error: Correct Private Key not found.\n";
        return "";
    }

    const PKA::Values pub_mpi = sec -> get_mpi();
    const PKA::Values pri_mpi = sec -> decrypt_secret_keys(passphrase);

    // get session key
    std::string session_key = zero + pka_decrypt(pka, session_key_mpi, pri_mpi, pub_mpi);   // symmetric algorithm, session key, 2 octet checksum wrapped in EME_PKCS1_ENCODE

    if (!(session_key = EME_PKCS1v1_5_DECODE(session_key, error)).size()){                  // remove EME_PKCS1 encoding
        error += "Error: EME_PKCS1v1_5_DECODE failure.\n";
        return "";
    }

    const uint8_t sym = session_key[0];                                                     // get symmetric algorithm
    std::string checksum = session_key.substr(session_key.size() - 2, 2);                   // get 2 octet checksum
    session_key = session_key.substr(1, session_key.size() - 3);                            // remove both from session key

    uint16_t sum = 0;
    for(char & c : session_key){                                                            // calculate session key checksum
        sum += static_cast <uint8_t> (c);
    }

    if (unhexlify(makehex(sum, 4)) != checksum){                                            // check session key checksums
        error += "Error: Calculated session key checksum does not match given checksum.\n";
        return "";
    }

    // decrypt the data with the extracted key
    PGPMessage decrypted = decrypt_data(sym, message, session_key, error);



    // if signing key provided, check the signature
    if (signer){
        if ((*verified = verify_message(*signer, decrypted, error)) == -1){
            error += "Error: Verification failure.\n";
        }
    }

    // extract data
    std::string out = "";
    for(Packet::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == Packet::LITERAL_DATA){
            out += std::static_pointer_cast <Tag11> (p) -> out(false);
        }
    }

    return out;
}

std::string decrypt_sym(const PGPMessage & message,
                        const std::string & passphrase,
                        std::string & error){
    if (!message.meaningful(error)){
        error += "Error: Bad message.\n";
        return "";
    }

    // find session key packet; should be first packet
    Tag3::Ptr tag3 = nullptr;
    for(Packet::Ptr const & p : message.get_packets()){
        if (p -> get_tag() == Packet::SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY){
            tag3 = std::static_pointer_cast <Tag3> (p);
            break;
        }
    }

    if (!tag3){
        error += "Error: No " + Packet::NAME.at(Packet::SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY) + " (Tag " + std::to_string(Packet::SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY) + ") found.\n";
        return "";
    }

    const std::string symkey = tag3 -> get_key(passphrase);
    const PGPMessage decrypted = decrypt_data(symkey[0], message, symkey.substr(1, symkey.size() - 1), error);

    // extract data
    std::string out = "";
    for(Packet::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == Packet::LITERAL_DATA){
            out += std::static_pointer_cast <Tag11> (p) -> out(false);
        }
    }

    return out;

}
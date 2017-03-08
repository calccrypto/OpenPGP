#include "decrypt.h"

Tag5::Ptr find_decrypting_key(const PGPSecretKey & k, const std::string & keyid){
    for(Packet::Ptr const & p : k.get_packets()){
        if ((p -> get_tag() == Packet::SECRET_KEY)   ||
            (p -> get_tag() == Packet::SECRET_SUBKEY)){
            Tag5::Ptr key = std::static_pointer_cast <Tag5> (p);
            if (key -> get_public_ptr() -> get_keyid() != keyid ){
                continue;
            }

            // make sure key has encrypting keys
            if (PKA::can_sign(key -> get_pka())){
                return key;
            }
        }
    }
    return nullptr;
}

std::string pka_decrypt(const uint8_t pka, PKA::Values & data, const PKA::Values & pri, const PKA::Values & pub){
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

PGPMessage decrypt_data(const uint8_t sym, const PGPMessage & m, const std::string & session_key, const bool writefile, const PGPPublicKey::Ptr & verify){
    // currently packet tag being operated on
    uint8_t tag;

    // get blocksize of symmetric key algorithm
    unsigned int BS = Sym::BLOCK_LENGTH.at(sym) >> 3;

    // Find encrypted data
    std::string data = "";

    // find start of encrypted data
    unsigned int i = 0;
    PGP::Packets packets = m.get_packets();
    while ((i < packets.size()) &&
           (packets[i] -> get_tag() != Packet::SYMMETRICALLY_ENCRYPTED_DATA) &&
           (packets[i] -> get_tag() != Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA)){
        i++;
    }

    // copy initial data to string
    if (packets[i] -> get_tag() == Packet::SYMMETRICALLY_ENCRYPTED_DATA){
        data = std::static_pointer_cast <Tag9> (packets[i]) -> get_encrypted_data();
        tag = Packet::SYMMETRICALLY_ENCRYPTED_DATA;
    }
    else if (packets[i] -> get_tag() == Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA){
        data = std::static_pointer_cast <Tag18> (packets[i]) -> get_protected_data();
        tag = Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA;
    }
    else{
        throw std::runtime_error("Error: No encrypted data found.");
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
        throw std::runtime_error("Error: No encrypted data packet(s) found.");
    }

    // decrypt data
    data = use_OpenPGP_CFB_decrypt(sym, tag, data, session_key);

    // strip extra data
    if (tag == Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA){
        std::string checksum = data.substr(data.size() - 20, 20);   // get given SHA1 checksum
        data = data.substr(0, data.size() - 20);                    // remove SHA1 checksum
        if (use_hash(Hash::SHA1, data) != checksum){            // check SHA1 checksum
            throw std::runtime_error("Error: Given checksum and calculated checksum do not match.");
        }
        data = data.substr(0, data.size() - 2);                     // get rid of \xd3\x14
    }
    data = data.substr(BS + 2, data.size() - BS - 2);               // get rid of prefix

    // decompress and parse decrypted data
    return PGPMessage(data);
}

std::string decrypt_pka(const PGPSecretKey & pri, const PGPMessage & m, const std::string & passphrase, const bool writefile, const PGPPublicKey::Ptr & verify){
    if ((m.get_type() != PGP::MESSAGE) //&&
        // (m.get_type() != PGP::MESSAGE_PART_XY) &&
        // (m.get_type() != PGP::MESSAGE_PART_X)
        ){
        throw std::runtime_error("Error: No encrypted message found.");
    }

    if (pri.get_type() != PGP::PRIVATE_KEY_BLOCK){
        throw std::runtime_error("Error: No Private Key found.");
    }

    // reused variables
    uint8_t tag;                                // currently used packet tag
    std::string data;                           // temp stuff
    std::string session_key;                    // session key
    uint8_t sym;                                // symmetric key algorithm used to encrypt original data

    // find session key packet; should be first packet
    for(Packet::Ptr const & p : m.get_packets()){
        if ((p -> get_tag() == Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY) ||
            (p -> get_tag() == Packet::SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY)){
            data = p -> raw();
            tag = p -> get_tag();
            break;
        }
    }

    if (tag == Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY){
        // return symmetrically-encrypted-key decrypted data
    }
    else if (tag == Packet::SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY){
        return decrypt_sym(m, passphrase);
    }
    else{
        throw std::runtime_error("Error: Expected Public-Key Encrypted Session Key Packet (Tag 1). Instead got " + Packet::NAME.at(tag) + " (Tag " + std::to_string(tag) + ").");
    }

    // Public-Key Encrypted Session Key Packet (Tag 1)
    Tag1 tag1(data);
    uint8_t pka = tag1.get_pka();
    PKA::Values session_key_mpi = tag1.get_mpi();

    // find corresponding secret key
    Tag5::Ptr sec = find_decrypting_key(pri, tag1.get_keyid());
    if (!sec){
        throw std::runtime_error("Error: Correct Private Key not found.");
    }

    PKA::Values pub_mpi = sec -> get_mpi();
    PKA::Values pri_mpi = sec -> decrypt_secret_keys(passphrase);

    // get session key
    session_key = zero + pka_decrypt(pka, session_key_mpi, pri_mpi, pub_mpi);     // symmetric algorithm, session key, 2 octet checksum wrapped in EME_PKCS1_ENCODE
    session_key = EME_PKCS1v1_5_DECODE(session_key);                              // remove EME_PKCS1 encoding
    sym = session_key[0];                                                         // get symmetric algorithm
    std::string checksum = session_key.substr(session_key.size() - 2, 2);         // get 2 octet checksum
    session_key = session_key.substr(1, session_key.size() - 3);                  // remove both from session key
    uint16_t sum = 0;
    for(char & c : session_key){                                                  // calculate session key checksum
        sum += static_cast <uint8_t> (c);
    }
    if (unhexlify(makehex(sum, 4)) != checksum){                                  // check session key checksums
        throw std::runtime_error("Error: Calculated session key checksum does not match given checksum.");
    }

    // decrypt the data with the extracted key
    PGPMessage decrypted = decrypt_data(sym, m, session_key, writefile, verify);

    std::string out = "";
    // if signing key provided, check the signature
    if (verify){
        out = "Message was" + std::string(verify_message(*verify, decrypted, out)?"":" not") + " signed by key " + hexlify(verify -> keyid()) + ".\n";
    }

    // extract data
    for(Packet::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == Packet::LITERAL_DATA){
            out += std::static_pointer_cast <Tag11> (p) -> out(writefile);
        }
    }

    return out;
}

std::string decrypt_sym(const PGPMessage & m, const std::string & passphrase, const bool writefile, const PGPPublicKey::Ptr & verify){
    std::cerr << "Warning: decrypt_sym is untested. Potentially incorrect" << std::endl;

    if ((m.get_type() != PGP::MESSAGE) //&&
        // (m.get_type() != PGP::MESSAGE_PART_XY) &&
        // (m.get_type() != PGP::MESSAGE_PART_X)
        ){
        throw std::runtime_error("Error: No encrypted message found.");
    }

    uint8_t packet;                             // currently used packet tag
    std::string data;                           // temp stuff

    // find session key packet; should be first packet
    for(Packet::Ptr const & p : m.get_packets()){
        if ((p -> get_tag() == Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY) ||
            (p -> get_tag() == Packet::SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY)){
            data = p -> raw();
            packet = p -> get_tag();
            break;
        }
    }

    if (packet == Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY){
        throw std::runtime_error("Error: Use decrypt_pka to decrypt this data.");
    }
    else if (packet == Packet::SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY){}
    else{
        throw std::runtime_error("Error: Expected Symmetric-Key Encrypted Session Key Packet (Tag 3). Instead got " + Packet::NAME.at(packet) + "(Tag " + std::to_string(packet) + ").");
    }

    data = Tag3(data).get_key(passphrase);

    PGPMessage decrypted = decrypt_data(data[0], m, data.substr(1, data.size() - 1), writefile, nullptr);

    std::string out = "";
    // extract data
    for(Packet::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == Packet::LITERAL_DATA){
            out += std::static_pointer_cast <Tag11> (p) -> out(writefile);
        }
    }
    return out;

}
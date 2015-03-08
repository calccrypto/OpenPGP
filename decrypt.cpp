#include "decrypt.h"

Tag5::Ptr find_decrypting_key(const PGPSecretKey & k, const std::string & keyid){
    for(Packet::Ptr const & p : k.get_packets()){
        if ((p -> get_tag() == 5) || (p -> get_tag() == 7)){
            std::string raw = p -> raw();
            Tag5::Ptr key = std::make_shared<Tag5>(raw);
            if (key -> get_public_ptr() -> get_keyid() != keyid ){
                key.reset();
                continue;
            }
            // make sure key has encrypting keys
            if ((key -> get_pka() == 1) || // RSA
                (key -> get_pka() == 2) || // RSA
                (key -> get_pka() == 16)){ // ElGamal
                    return key;
            }
            key.reset();
        }
    }
    return nullptr;
}

std::string pka_decrypt(const uint8_t pka, std::vector <PGPMPI> & data, const std::vector <PGPMPI> & pri, const std::vector <PGPMPI> & pub){
    if (pka < 3){   // RSA
        return mpitoraw(RSA_decrypt(data[0], pri, pub));
    }
    if (pka == 16){ // ElGamal
        return ElGamal_decrypt(data, pri, pub);
    }
    else{
        std::stringstream s; s << static_cast <unsigned int> (pka);
        throw std::runtime_error("Error: PKA number " + s.str() + " not allowed or unknown.");
    }
    return ""; // should never reach here; mainly just to remove compiler warnings
}

std::vector <PGPMPI> decrypt_secret_key(const Tag5::Ptr & pri, const std::string & passphrase){
    std::vector <PGPMPI> out;
    S2K::Ptr s2k = pri -> get_s2k();

    // calculate key used in encryption algorithm
    std::string key = s2k -> run(passphrase, Symmetric_Algorithm_Key_Length.at(Symmetric_Algorithms.at(pri -> get_sym())) >> 3);

    // decrypt secret key
    std::string secret_key = use_normal_CFB_decrypt(pri -> get_sym(), pri -> get_secret(), key, pri -> get_IV());

    // get checksum and remove it from the string
    const unsigned int hash_size = (pri -> get_s2k_con() == 254)?20:2;
    std::string checksum = secret_key.substr(secret_key.size() - hash_size, hash_size);
    secret_key = secret_key.substr(0, secret_key.size() - hash_size);

    // calculate and check checksum
    if(pri -> get_s2k_con() == 254){
        if (use_hash(s2k -> get_hash(), secret_key) != checksum){
            throw std::runtime_error("Error: Secret key checksum and calculated checksum do not match.");
        }
    }
    else{ // all other values; **UNTESTED**
        uint16_t sum = 0;
        for(char & c : secret_key){
            sum += static_cast <unsigned char> (c);
        }
        if (unhexlify(makehex(sum, 4)) != checksum){
            if (use_hash(s2k -> get_hash(), secret_key) != checksum){
                throw std::runtime_error("Error: Secret key checksum and calculated checksum do not match.");
            }
        }
    }

    // extract MPI values
    while (secret_key.size()){
        out.push_back(read_MPI(secret_key));
    }

    s2k.reset();

    return out;
}

PGPMessage decrypt_data(const uint8_t sym, const PGPMessage & m, const std::string & session_key, const bool writefile, const PGPPublicKey::Ptr & verify){
    // currently packet tag being operated on
    uint8_t packet;

    // get blocksize of symmetric key algorithm
    unsigned int BS = Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(sym)) >> 3;

    // Find encrypted data
    std::string data = "";

    // find start of encrypted data
    unsigned int i = 0;
    std::vector <Packet::Ptr> packets = m.get_packets();
    while ((i < packets.size()) && (packets[i] -> get_tag() != 9) && (packets[i] -> get_tag() != 18)){
        i++;
    }

    // copy initial data to string
    if (packets[i] -> get_tag() == 9){
        data = packets[i] -> raw();
        Tag9 tag9(data);
        data = tag9.get_encrypted_data();
        packet = 9;
    }
    else if (packets[i] -> get_tag() == 18){
        data = packets[i] -> raw();
        Tag18 tag18(data);
        data = tag18.get_protected_data();
        packet = 18;
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
    data = use_OpenPGP_CFB_decrypt(sym, packet, data, session_key);

    // strip extra data
    if (packet == 18){ // Symmetrically Encrypted Integrity Protected Data Packet (Tag 18)
        std::string checksum = data.substr(data.size() - 20, 20);   // get given SHA1 checksum
        data = data.substr(0, data.size() - 20);                    // remove SHA1 checksum
        if (use_hash(2, data) != checksum){                         // check SHA1 checksum
            throw std::runtime_error("Error: Given checksum and calculated checksum do not match.");
        }
        data = data.substr(0, data.size() - 2);                     // get rid of \xd3\x14
    }
    data = data.substr(BS + 2, data.size() - BS - 2);               // get rid of prefix

    // decompress and parse decrypted data
    return PGPMessage(data);
}

std::string decrypt_pka(const PGPSecretKey & pri, const PGPMessage & m, const std::string & passphrase, const bool writefile, const PGPPublicKey::Ptr & verify){
    if ((m.get_ASCII_Armor() != 0)/* && (m.get_ASCII_Armor() != 3) && (m.get_ASCII_Armor() != 4)*/){
        throw std::runtime_error("Error: No encrypted message found.");
    }

    if (pri.get_ASCII_Armor() != 2){
        throw std::runtime_error("Error: No Private Key found.");
    }

    // reused variables
    uint8_t packet;                             // currently used packet tag
    std::string data;                           // temp stuff
    std::string session_key;                    // session key
    uint8_t sym;                                // symmetric key algorithm used to encrypt original data

    // find session key packet; should be first packet
    for(Packet::Ptr const & p : m.get_packets()){
        if ((p -> get_tag() == 1) || (p -> get_tag() == 3)){
            data = p -> raw();
            packet = p -> get_tag();
            break;
        }
    }

    if (packet == 1){}
    // return symmetrically-encrypted-key decrypted data
    else if (packet == 3){
        return decrypt_sym(m, passphrase);
    }
    else{
        std::stringstream s; s << Packet_Tags.at(packet) << " (Tag " << static_cast <unsigned int> (packet) << ").";
        throw std::runtime_error("Error: Expected Public-Key Encrypted Session Key Packet (Tag 1). Instead got " + s.str());
    }

    // Public-Key Encrypted Session Key Packet (Tag 1)
    Tag1 tag1(data);
    uint8_t pka = tag1.get_pka();
    std::vector <PGPMPI> session_key_mpi = tag1.get_mpi();

    // find corresponding secret key
    Tag5::Ptr sec = find_decrypting_key(pri, tag1.get_keyid());
    if (!sec){
        throw std::runtime_error("Error: Correct Private Key not found.");
    }

    std::vector <PGPMPI> pub_mpi = sec -> get_mpi();
    std::vector <PGPMPI> pri_mpi = decrypt_secret_key(sec, passphrase);

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

    sec.reset();

    // decrypt the data with the extracted key
    PGPMessage decrypted = decrypt_data(sym, m, session_key, writefile, verify);

    std::string out = "";
    // if signing key provided, check the signature
    if (verify){
        out = "Message was" + std::string(verify_message(*verify, decrypted)?"":" not") + " signed by key " + hexlify(verify -> keyid()) + ".\n";
    }

    // extract data
    for(Packet::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == 11){
            std::string raw = p -> raw();
            Tag11 tag11(raw);
            out += tag11.out(writefile);
        }
    }

    return out;
}

std::string decrypt_sym(const PGPMessage & m, const std::string & passphrase, const bool writefile, const PGPPublicKey::Ptr & verify){
    std::cerr << "Warning: decrypt_sym is untested. Potentially incorrect" << std::endl;

    if ((m.get_ASCII_Armor() != 0)/* && (m.get_ASCII_Armor() != 3) && (m.get_ASCII_Armor() != 4)*/){
        throw std::runtime_error("Error: No encrypted message found.");
    }

    uint8_t packet;                             // currently used packet tag
    std::string data;                           // temp stuff

    // find session key packet; should be first packet
    for(Packet::Ptr const & p : m.get_packets()){
        if ((p -> get_tag() == 1) || (p -> get_tag() == 3)){
            data = p -> raw();
            packet = p -> get_tag();
            break;
        }
    }

    if (packet == 1){
        throw std::runtime_error("Error: Use decrypt_pka to decrypt this data.");
    }
    else if (packet == 3){}
    else{
        std::stringstream s; s << Packet_Tags.at(packet) << " (Tag " << static_cast <unsigned int> (packet) << ").";
        throw std::runtime_error("Error: Expected Symmetric-Key Encrypted Session Key Packet (Tag 3). Instead got " + s.str());
    }

    Tag3 tag3(data);
    data = tag3.get_key(passphrase);

    PGPMessage decrypted = decrypt_data(data[0], m, data.substr(1, data.size() - 1), writefile, nullptr);

    std::string out = "";
    // extract data
    for(Packet::Ptr const & p : decrypted.get_packets()){
        if (p -> get_tag() == 11){
            std::string raw = p -> raw();
            Tag11 tag11(raw);
            out += tag11.out(writefile);
        }
    }
    return out;

}
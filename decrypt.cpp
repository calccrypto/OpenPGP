#include "decrypt.h"

Tag5::Ptr find_decrypting_key(const PGP & k, const std::string &keyid){
    if (k.get_ASCII_Armor() == 2){
        std::vector <Packet::Ptr> packets = k.get_packets();
        for(Packet::Ptr const & p : packets){
            if ((p -> get_tag() == 5) || (p -> get_tag() == 7)){
                std::string data = p -> raw();
                Tag5::Ptr key = std::make_shared<Tag5>(data);
                if ( key->get_public_ptr()->get_keyid() != keyid ){
                    continue;
                }
                // make sure key has signing material
                if ((key -> get_pka() == 1) || // RSA
                    (key -> get_pka() == 2) || // RSA
                    (key -> get_pka() == 16)){ // ElGamal
                        return key;
                }
            }
        }
    }
    return Tag5::Ptr();
}

std::string pka_decrypt(const uint8_t pka, std::vector <PGPMPI> & data, const std::vector <PGPMPI> & pri, const std::vector <PGPMPI> & pub){
    if (pka < 3){   // RSA
        return mpitoraw(RSA_decrypt(data[0], pri, pub));
    }
    if (pka == 16){ // ElGamal
        return ElGamal_decrypt(data, pri, pub);
    }
    else{
        std::stringstream s; s << static_cast <int> (pka);
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
    return out;
}

std::string decrypt_message(PGP & m, PGP& pri, const std::string & passphrase){
    if ((m.get_ASCII_Armor() != 0)/* && (m.get_ASCII_Armor() != 3) && (m.get_ASCII_Armor() != 4)*/){
        throw std::runtime_error("Error: No encrypted message found.");
    }

    if (pri.get_ASCII_Armor() != 2){
        throw std::runtime_error("Error: No Private Key found.");
    }
    // reused variables
    uint8_t packet;
    std::string data;
    std::string checksum;

    std::string session_key;                    // session key
    uint8_t sym;                                // symmetric key algorithm used to encrypt original data
    unsigned int BS;                            // blocksize of symmetric key algorithm

    // find session key
    std::vector <Packet::Ptr> message_packets = m.get_packets();
    for(Packet::Ptr const & p : message_packets){
        if ((p -> get_tag() == 1) || (p -> get_tag() == 3)){
            data = p -> raw();
            packet = p -> get_tag();
            break;
        }
    }
   
    if (packet == 1){ // Public-Key Encrypted Session Key Packet (Tag 1)
        Tag1 tag1(data);
        uint8_t pka = tag1.get_pka();
        std::vector <PGPMPI> session_key_mpi = tag1.get_mpi();

        // find corresponding secret key
        Tag5::Ptr sec = find_decrypting_key(pri, tag1.get_keyid());

        if (!sec){
            throw std::runtime_error("Error: Correct Private Key not found.");
        }

        std::vector <PGPMPI> pub = sec -> get_mpi();
        std::vector <PGPMPI> pri = decrypt_secret_key(sec, passphrase);

        // get session key
        session_key = zero + pka_decrypt(pka, session_key_mpi, pri, pub);                   // symmetric algorithm, session key, 2 octet checksum wrapped in EME_PKCS1_ENCODE
        session_key = EME_PKCS1v1_5_DECODE(session_key);                                    // remove EME_PKCS1 encoding
        sym = session_key[0];                                                               // get symmetric algorithm
        checksum = session_key.substr(session_key.size() - 2, 2);                           // get 2 octet checksum
        session_key = session_key.substr(1, session_key.size() - 3);                        // remove both from session key
        uint16_t sum = 0;
        for(char & c : session_key){                                                        // calculate session key checksum
            sum += static_cast <uint8_t> (c);
        }
        if (unhexlify(makehex(sum, 4)) != checksum){                                        // check session key checksums
            throw std::runtime_error("Error: Calculated session key checksum does not match given checksum.");
        }
    }
    else if (packet == 3){ //Symmetric-Key Encrypted Session Key Packet (Tag 3)
        /* untested */
        Tag3 tag3(data);
        data = tag3.get_key(passphrase);
        sym = data[0];
        session_key = data.substr(1, data.size() - 1);
    }
    else{
        throw std::runtime_error("Error: No session key packet found.");
    }

    BS = Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(sym)) >> 3;           // get blocksize

    // Find encrypted data
    data = "";
    for(Packet::Ptr const & p : message_packets){
        if (p -> get_tag() == 9){
            data = p -> raw();
            Tag9 tag9(data);
            data = tag9.get_encrypted_data();
            packet = 9;
            break;
        }
        else if (p -> get_tag() == 18){
            data = p -> raw();
            Tag18 tag18(data);
            data = tag18.get_protected_data();
            packet = 18;
            break;
        }
    }
    if (!data.size()){
        throw std::runtime_error("Error: No encrypted data packets found.");
    }

    if (sym == 2){ // Triple DES
        data = use_OpenPGP_CFB_decrypt(sym, packet, data, session_key.substr(0, 8), session_key.substr(8, 8), session_key.substr(16, 8)); // decrypt encrypted data
    }
    else{
        data = use_OpenPGP_CFB_decrypt(sym, packet, data, session_key); // decrypt encrypted data
    }
    
    if (packet == 18){ // Symmetrically Encrypted Integrity Protected Data Packet (Tag 18)
        checksum = data.substr(data.size() - 20, 20);       // get given SHA1 checksum
        data = data.substr(0, data.size() - 20);            // remove SHA1 checksum
        if (use_hash(2, data) != checksum){                 // check SHA1 checksum
            throw std::runtime_error("Error: Given checksum and calculated checksum do not match.");
        }
        data = data.substr(0, data.size() - 2);             // get rid of \xd3\x14
    }
    
    data = data.substr(BS + 2, data.size() - BS - 2);       // get rid of prefix
  
    if (packet == 9){ // Symmetrically Encrypted Data Packet (Tag 9)               
        // figure out which compression algorithm was used
        // uncompressed literal data packet
        if ((data[0] == 'b') || (data[0] == 't') || (data[0] == 'u')){
            data = Tag11(data).write(); // add in Tag11 headers to be removed later
        }
        // BZIP2
        else if (data.substr(0, 2) == "BZ"){
            data = PGP_decompress(3, data);
        }
        // ZLIB
        else if ((data.substr(0, 2) == "\x78\x01") || (data.substr(0, 2) == "\x78\x9c") || (data.substr(0, 2) == "\x78\xda")){
            data = PGP_decompress(2, data);
        }
        // DEFLATE
        else{
            data = PGP_decompress(1, data);
        }
    }

    // get rid of header and figure out what type of packet data it is
    bool format;
    data = read_packet_header(data, packet, format);

    // output data
    switch (packet){
        case 8: // Compressed Data Packet
            {
                data = Tag8(data).get_data(); // compressed packets
                std::vector <Packet::Ptr> compressed_packets;
                
                while (data.size()){ // extract packets
                    compressed_packets.push_back(read_packet(data) -> clone());
                }
                
                // extract all packet data; probably needs better formatting
                for(const Packet::Ptr & p : compressed_packets){
                    if (p -> get_tag() == 11){
                        Tag11 tag11(data);
                        if (tag11.get_filename() == ""){
                            data += tag11.get_literal();
                        }
                        else{
                            tag11.write();
                            data += "Data written to file '" + Tag11(data).get_filename() + "'";
                        }
                        std::cout << data << std::endl;
                    }
                    // else{
                        // data += p -> show() + "\n";
                    // }
                }
            }
            break;
        case 11: // Literal Data Packet
            {
                Tag11 tag11(data);
                if (tag11.get_filename() == ""){
                    data = tag11.get_literal();
                }
                else{
                    tag11.write();
                    data = "Data written to file '" + Tag11(data).get_filename() + "'";
                }
            }
            break;
        default:
            {
                std::stringstream s; s << packet;
                throw std::runtime_error("Error: No action defined for packet type " + s.str());
            }
            break;
    }
    return data;
}

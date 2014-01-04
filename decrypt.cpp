#include "decrypt.h"

Tag5 * find_decrypting_key(PGP & k){
    if (k.get_ASCII_Armor() == 2){
        std::vector <Packet *> packets = k.get_packets();
        for(Packet *& p : packets){
            if ((p -> get_tag() == 5) || (p -> get_tag() == 7)){
                std::string data = p -> raw();
                Tag5 * key = new Tag5(data);
                // make sure key has signing material
                if ((key -> get_pka() == 1) || // RSA
                    (key -> get_pka() == 2) || // RSA
                    (key -> get_pka() == 16)){ // ElGamal
                        return key;
                }
                delete key;
            }
        }
    }
    return NULL;
}

std::string pka_decrypt(const uint8_t pka, std::vector <mpz_class> & data, const std::vector <mpz_class> & pri, const std::vector <mpz_class> & pub){
    if (pka < 3){   // RSA
        std::string out = RSA_decrypt(data[0], pri, pub).get_str(16);
        out = std::string(out.size() & 1, '0') + out;
        return unhexlify(out);
    }
    if (pka == 16){ // ElGamal
        return ElGamal_decrypt(data, pri, pub);
    }
    else{
        std::cerr << "Error: PKA number " << pka << " not allowed or unknown." << std::endl;
        throw 1;
    }
    return ""; // should never reach here; mainly just to remove compiler warnings
}

std::vector <mpz_class> decrypt_secret_key(Tag5 * pri, const std::string & passphrase){
    std::vector <mpz_class> out;
    S2K * s2k = pri -> get_s2k();

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
            std::cerr << "Error: Secret key checksum and calculated checksum do not match." << std::endl;
            throw 1;
        }
    }
    else{ // all other values; **UNTESTED**
        uint16_t sum = 0;
        for(char & c : secret_key){
            sum += (unsigned char) c;
        }
        if (unhexlify(makehex(sum, 4)) != checksum){
            if (use_hash(s2k -> get_hash(), secret_key) != checksum){
                std::cerr << "Error: Secret key checksum and calculated checksum do not match." << std::endl;
                throw 1;
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
        std::cerr << "Error: No encrypted message found." << std::endl;
        throw 1;
    }

    if (pri.get_ASCII_Armor() != 2){
        std::cerr << "Error: No Private Key found." << std::endl;
        throw 1;
    }

    // reused variables
    uint8_t packet;
    std::string data;
    std::string checksum;

    std::string session_key;                    // session key
    uint8_t sym;                                // symmmetric key algorithm used to encrypt original data
    unsigned int BS;                            // blocksize of symmetric key algorithm

    // find session key
    std::vector <Packet *> message_packets = m.get_packets();
    for(Packet *& p : message_packets){
        if ((p -> get_tag() == 1) || (p -> get_tag() == 3)){
            data = p -> raw();
            packet = p -> get_tag();
            break;
        }
    }

    if (packet == 1){ // Public-Key Encrypted Session Key Packet (Tag 1)
        Tag1 tag1(data);
        uint8_t pka = tag1.get_pka();
        std::vector <mpz_class> session_key_mpi = tag1.get_mpi();

        // find corresponding secret key
        Tag5 * sec = find_decrypting_key(pri);

        if (!sec){
            std::cerr << "Error: Correct Private Key not found." << std::endl;
            throw 1;
        }

        std::vector <mpz_class> pub = sec -> get_mpi();
        std::vector <mpz_class> pri = decrypt_secret_key(sec, passphrase);

        // get session key
        session_key = zero + pka_decrypt(pka, session_key_mpi, pri, pub);                   // symmetric algorithm, session key, 2 octet checksum wrapped in EME_PKCS1_ENCODE
        session_key = EME_PKCS1v1_5_DECODE(session_key);                                    // remove EME_PKCS1 encoding

        sym = session_key[0];                                                               // get symmetric algorithm
        checksum = session_key.substr(session_key.size() - 2, 2);                           // get 2 octet checksum
        session_key = session_key.substr(1, session_key.size() - 3);                        // remove both from session key
        uint16_t sum = 0;
        for(char & c : session_key){                                                        // calculate session key checksum
            sum += (unsigned uint8_t) c;
        }
        if (unhexlify(makehex(sum, 4)) != checksum){                                        // check session key checksums
            std::cerr << "Error: Calculated session key checksum does not match given checksum." << std::endl;
            delete sec;
            throw 1;
        }
        delete sec;
    }
    else if (packet == 3){ //Symmetric-Key Encrypted Session Key Packet (Tag 3)
        /* untested */
        Tag3 tag3(data);
        data = tag3.get_key(passphrase);
        sym = data[0];
        session_key = data.substr(1, data.size() - 1);
    }
    else{
        std::cerr << "Error: No session key packet found." << std::endl;
        throw 1;
    }

    BS = Symmetric_Algorithm_Block_Length.at(Symmetric_Algorithms.at(sym)) >> 3;        // get blocksize

    // Find encrypted data
    data = "";
    for(Packet *& p : message_packets){
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
        std::cerr << "Error: No encrypted data packets found." << std::endl;
        throw 1;
    }

    if (sym == 2){ // Triple DES
        data = use_OpenPGP_CFB_decrypt(sym, packet, data, session_key.substr(0, 8), session_key.substr(8, 8), session_key.substr(16, 8)); // decrypt encrypted data
    }
    else{
        data = use_OpenPGP_CFB_decrypt(sym, packet, data, session_key); // decrypt encrypted data
    }

    // clean up decrypted data for output
    if (packet == 9){ // Symmetrically Encrypted Data Packet (Tag 9)
        data = data.substr(BS + 2, data.size() - BS - 2);   // get rid of header
        if (data[0] < 4){
            packet = 8;
        }
        else if ((data[0] == 'b') || (data[0] == 't') || (data[0] == 'u')){
            packet = 11;
        }
        else{
            std::cerr << "Error: Unknown output format." << std::endl;
            throw 1;
        }
    }
    else if (packet == 18){ // Symmetrically Encrypted Integrity Protected Data Packet (Tag 18)
        checksum = data.substr(data.size() - 20, 20);       // get given SHA1 checksum
        data = data.substr(0, data.size() - 20);            // remove SHA1 checksum
        if (use_hash(2, data) != checksum){                 // check SHA1 checksum
            std::cerr << "Error: Given Checksum and calculated checksum do not match." << std::endl;
            throw 1;
        }
        data = data.substr(0, data.size() - 2);             // get rid of \xd3\x14
        data = data.substr(BS + 2, data.size() - BS - 2);   // get rid of header
        bool format;                                        // junk variable
        data = read_packet_header(data, packet, format);    // get rid of header and figure out what type of packet data it is
    }

    // extract data for output
    if (packet == 8){ // Compressed Data Packet (Tag 8)
        // can't use unless/until compression algorithms are implemented
//        Tag8 tag8(data);
//        data = tag8.get_data();
        data = "Data in hex, so its easier to copy to a " + Compression_Algorithms.at(data[0]) + " decompressor:\n\n" + hexlify(data.substr(1, data.size() - 1));
    }
    else if (packet == 11){ // Literal Data Packet (Tag 11)
        Tag11 tag11(data);
        data = tag11.get_literal();
        // take out for now
//        if (tag11.get_format() == 'b'){
//            std::ofstream f(tag11.get_filename(), std::ios::binary);
//            f << data;
//            data = "Data written to file '" + tag11.get_filename() + "'";
//        }
    }
    return data;
}

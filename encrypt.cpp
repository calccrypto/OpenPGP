#include "encrypt.h"

Packet::Ptr encrypt_data(const EncryptArgs & args,
                         const std::string & session_key,
                         std::string & error){
    // put data in Literal Data Packet
    Tag11 tag11;
    tag11.set_format('t');
    tag11.set_filename(args.filename);
    tag11.set_time(0);
    tag11.set_literal(args.data);

    std::string to_encrypt = tag11.write(2);

    if (args.comp){
        // Compressed Data Packet (Tag 8)
        Tag8 tag8;
        tag8.set_comp(args.comp);
        tag8.set_data(to_encrypt); // put source data into compressed packet
        to_encrypt = tag8.write(2);
    }

    // generate prefix
    const std::size_t BS = Sym::BLOCK_LENGTH.at(args.sym);
    std::string prefix = integer(BBS().rand(BS), 2).str(256, BS >> 3);

    Packet::Ptr encrypted = nullptr;

    if (!args.mdc){
        // Symmetrically Encrypted Data Packet (Tag 9)
        Tag9 tag9;
        tag9.set_encrypted_data(use_OpenPGP_CFB_encrypt(args.sym, Packet::SYMMETRICALLY_ENCRYPTED_DATA, to_encrypt, session_key, prefix));
        encrypted = std::make_shared <Tag9> (tag9);
    }
    else{
        // Modification Detection Code Packet (Tag 19)
        Tag19 tag19;
        tag19.set_hash(use_hash(Hash::SHA1, prefix + prefix.substr((BS >> 3) - 2, 2) + to_encrypt + "\xd3\x14"));

        // Sym. Encrypted Integrity Protected Data Packet (Tag 18)
        // encrypt(compressed(literal_data_packet(plain text)) + MDC SHA1(20 octets))
        Tag18 tag18;
        tag18.set_protected_data(use_OpenPGP_CFB_encrypt(args.sym, Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA, to_encrypt + tag19.write(), session_key, prefix));
        encrypted = std::make_shared <Tag18> (tag18);
    }

    return encrypted;
}

PGPMessage encrypt_pka(const EncryptArgs & args,
                       const PGPKey & key,
                       std::string & error){
    BBS(static_cast <PGPMPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded

    if (!key.meaningful(error)){
        error += "Error: No encrypting key found.";
        return PGPMessage();
    }

    // Check if key has been revoked
    const int rc = check_revoked(key, error);
    if (rc == 1){
        error += "Error: Key " + hexlify(key.keyid()) + " has been revoked. Nothing done.";
        return PGPMessage();
    }
    else if (rc == -1){
        error += "Error: check_revoked failed.\n";
        return PGPMessage();
    }

    Tag6::Ptr public_key = nullptr;
    for(Packet::Ptr const & p : key.get_packets()){
        public_key = nullptr;
        if (Packet::is_key_packet(p -> get_tag())){
            public_key = std::static_pointer_cast <Tag6> (p);

            // make sure key has encrypting keys
            if (PKA::can_encrypt(public_key -> get_pka())){
                break;
            }
        }
    }

    if (!public_key){
        error += "Error: No encrypting key found.";
        return PGPMessage();
    }

    PKA::Values mpi = public_key -> get_mpi();
    Tag1::Ptr tag1 = std::make_shared <Tag1> ();
    tag1 -> set_keyid(public_key -> get_keyid());
    tag1 -> set_pka(public_key -> get_pka());

    // do calculations

    // generate session key
    std::size_t key_len = Sym::KEY_LENGTH.at(args.sym);

    // get hex version of session key
    std::string session_key = mpitohex(bintompi(BBS().rand(key_len)));

    // unhexlify session key
    session_key = unhexlify(std::string((key_len >> 2) - session_key.size(), '0') + session_key);

    // get checksum of session key
    uint16_t sum = 0;
    for(char & x : session_key){
        sum += static_cast <unsigned char> (x);
    }

    std::string nibbles = mpitohex(mpi[0]);        // get hex representation of modulus
    nibbles += std::string(nibbles.size() & 1, 0); // get even number of nibbles
    PGPMPI m = hextompi(hexlify(EME_PKCS1v1_5_ENCODE(std::string(1, args.sym) + session_key + unhexlify(makehex(sum, 4)), nibbles.size() >> 1, error)));

    // encrypt m
    if ((public_key -> get_pka() == PKA::RSA_ENCRYPT_OR_SIGN) ||
        (public_key -> get_pka() == PKA::RSA_ENCRYPT_ONLY)){
        tag1 -> set_mpi({RSA_encrypt(m, mpi)});
    }
    if (public_key -> get_pka() == PKA::ELGAMAL){
        tag1 -> set_mpi(ElGamal_encrypt(m, mpi));
    }

    // encrypt data and put it into a packet
    Packet::Ptr encrypted = encrypt_data(args, session_key, error);

    // write data to output container
    PGPMessage out;
    out.set_keys({std::make_pair("Version", "cc")});
    out.set_packets({tag1, encrypted});

    return out;
}

PGPMessage encrypt_sym(const EncryptArgs & args,
                       const std::string & passphrase,
                       std::string & error){
    BBS(static_cast <PGPMPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded

    // String to Key specifier for decrypting session key
    S2K3::Ptr s2k = std::make_shared <S2K3> ();
    s2k -> set_type(S2K::ITERATED_AND_SALTED_S2K);
    s2k -> set_hash(Hash::SHA1);
    s2k -> set_salt(integer(BBS().rand(64), 2).str(256, 8));
    s2k -> set_count(96);

    // generate Symmetric-Key Encrypted Session Key Packets (Tag 3)
    Tag3::Ptr tag3 = std::make_shared <Tag3> ();
    tag3 -> set_version(4);
    tag3 -> set_sym(args.sym);
    tag3 -> set_s2k(s2k);

    // generate session key
    const std::string session_key = tag3 -> get_session_key(passphrase);

    // encrypt data
    Packet::Ptr encrypted = encrypt_data(args, session_key.substr(1, session_key.size() - 1), error);

    // write to output container
    PGPMessage out;
    out.set_keys({std::make_pair("Version", "cc")});
    out.set_packets({tag3, encrypted});

    return out;
}

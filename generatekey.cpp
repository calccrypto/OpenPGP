#include "generatekey.h"

bool fill_key_sigs(PGPSecretKey & private_key, const std::string & passphrase, std::string & error){
    BBS(static_cast <PGPMPI> (static_cast <uint32_t> (now()))); // seed just in case not seeded

    if (!private_key.meaningful(error)){
        error += "Error: Bad key.\n";
        return false;
    }

    const std::string keyid = private_key.keyid();
    const Tag5::Ptr primary = std::static_pointer_cast <Tag5> (private_key.get_packets()[0]);
    PGP::Packets packets = private_key.get_packets_clone();

    Key::Ptr key = nullptr;
    User::Ptr user = nullptr;

    for(Packet::Ptr & p : packets){
        if (Packet::is_key_packet(p -> get_tag())){
            key = std::static_pointer_cast <Key> (p);
            user = nullptr;
        }
        else if (Packet::is_user(p -> get_tag())){
            user = std::static_pointer_cast <User> (p);
        }
        else if (p -> get_tag() == Packet::SIGNATURE){
            Tag2::Ptr sig = std::static_pointer_cast <Tag2> (p);

            // only fill in keys that are supposed to be signed by the primary key
            // don't fill in empty key IDs
            if (sig -> get_keyid() == keyid){
                if (Signature_Type::is_certification(sig -> get_type())){
                    if (key -> get_tag() == Packet::SECRET_KEY){
                        const Tag5::Ptr tag5 = std::static_pointer_cast <Tag5> (key);
                        sig = sign_primary_key(primary, passphrase, tag5, user, sig, error);
                    }
                    else{
                        error += "Error: Certification signature attempted to be made for a non-primary key.\n";
                        return false;
                    }
                }
                else if (sig -> get_type() == Signature_Type::SUBKEY_BINDING_SIGNATURE){
                    if (key -> get_tag() == Packet::SECRET_SUBKEY){
                        const Tag7::Ptr tag7 = std::static_pointer_cast <Tag7> (key);
                        sig = sign_subkey_binding(primary, passphrase, tag7, sig, error);
                    }
                    else{
                        error += "Error: Subkey Binding signature attempted to be made for a non-subkey.\n";
                        return false;
                    }
                }
                else if (sig -> get_type() == Signature_Type::KEY_REVOCATION_SIGNATURE){
                    sig = revoke_sig(primary, passphrase, primary, sig, error);
                }
                else if (sig -> get_type() == Signature_Type::SUBKEY_REVOCATION_SIGNATURE){
                    sig = revoke_sig(primary, passphrase, key, sig, error);
                }
                else if (sig -> get_type() == Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE){
                    sig = revoke_uid_sig(primary, passphrase, user, sig, error);
                }
                else{
                    std::cerr << "Warning: Bad or unhandled signature type: 0x" << makehex(sig -> get_type(), 2) << std::endl;
                }
            }
        }
        else{
            // should never come here
            error += "Error: Random packet found.\n";
            return false;
        }
    }

    private_key.set_packets(packets);

    return true;
}

PGPSecretKey generate_key(KeyGen & config, std::string & error){
    BBS(static_cast <PGPMPI> (static_cast <uint32_t> (now()))); // seed just in case not seeded

    if (!config.valid(error)){
        error += "Error: Bad key generation configuration.\n";
        return PGPSecretKey();
    }

    // collection of packets to be put into final key
    PGP::Packets packets;

    // Key creation time
    const time_t time = now();

    // generate Primary Key, User ID, and Signature packets

    // generate public key values for primary key
    PKA::Values pub;
    PKA::Values pri;
    if (!generate_keypair(config.pka, generate_pka_params(config.pka, config.bits >> 1), pri, pub)){
        error += "Error: Could not generate primary key pair.\n";
        return PGPSecretKey();
    }

    // pub = {
        // hextompi("a2f705210d5cfefd4c10f83df7a55ef22736e2e88ac7aaa0be23dc13b79e61e1698d091e0db64171aa14d037393e45106249cd03f5da24e5d038d702e8895a91de1127756015d946cad0702617aec05d883dd719364a646a87337c350a62d7fd9324f7f1c9691b2fda7b1df642665b8698ab7b72e5c45d9a3d20f74c7f7f8bc8edd3b5f6173f9d428b66848b4619c38707fe07937d1d1def88971b8edb13ca22b946bd0967b61d127102a48213e992500a002568d7e9ceb6d77d125348317403d5725126953a56e97157dcf4d250b4ce1c3c0434d94882a7be356624b6b514efd999bdbdf2bfd520fa9f2a28ce560578af2999c62af209fa23051133ee516e75"),
        // hextompi("10001"),
    // };

    // pri = {
        // hextompi("1123929605ce4481063978aa27bbec2ee281eabe532e299b4b340146cf96682be94a6c6d8d3aa04a607d5ce299f21b185c85ef7a5da66a2003549f044ec9774d8501dfd8ffd87c67ee179adbdebcc1bd7481307895d5a016f60e2b9f766eabd19ee291f30b6032fc46e990de9fe01cfb1c5e5896de645705cc2d05e53539884d57f100309f49cb4a0235cf402f1bd8a61dbd89f64ca3557298ce81e71cf701583a54bce3492daa94167a5370aeadfbc273dc93b2994e2828b0d19a820600025c4f21c021ebc52c48de3da19a048971901d12a0f650f03478522908e07895372731bd0b9bb6811bb9ffe021f9b29dbc3cc383a92aa582866f1119635d199ddb41"),
        // hextompi("c0c96e1ef316dc71f7a21499b14922dc8129b7e018678b1835ba98492789a10751731785c9bad5fd3d3ec03831dec56490d7f1e68aeed626a227aaf65cbdc5736e6bac4fd193225f4c53901b87a35afda564b8923e09142d762d2310ad851bde45346742d1f5dc3d3369e51333f067a40656eaa934ce464da183914199df9bd5"),
        // hextompi("d86654eda6666c9f1f76e7b9edf44630a660248c4782c76afd77ecc9a70e3e74771321e1f47311ae9888bf173c53ea9937dc5179d50ef9204843d7950f2e5ca2ce76b5a3a465127aa30ebe2e78a90064ac723b33b4645a9b1761c0fd23b32168755ade989d5044bab6ce186d7a2dcc3d4c152942dbb037de5e17c226ff68f821"),
        // hextompi("9f6099570d583b2467f8ba6bcc8242738f212673bec4168320cf8a3fa3ece0d3cf3ffb3ebda4369a5f4b18cc9fc846e348f6cdff67a0012ebf55fdf812859d5be4e78809733a7bfdbb6ca14ad7f5f92b1e23ec5a44f81d0134a124f9f5e4ea13ccfce3fa40470ff73f71b7b9100a0155fcccf00c183e026de35533f0fd79b758"),
    // };

    // convert the secret values into a string
    std::string secret;
    for(PGPMPI const & mpi : pri){
        secret += write_MPI(mpi);
    }

    // Secret Key Packet
    Tag5::Ptr primary = std::make_shared <Tag5> ();
    primary -> set_version(4);
    primary -> set_time(time);
    primary -> set_pka(config.pka);
    primary -> set_mpi(pub);
    primary -> set_s2k_con(0); // no passphrase up to here

    // encrypt secret only if there is a passphrase
    if (config.passphrase.size()){
        primary -> set_s2k_con(254);
        primary -> set_sym(config.sym);

        // Secret Key Packet S2K
        S2K3::Ptr s2k3 = std::make_shared <S2K3> ();
        s2k3 -> set_hash(config.hash);
        s2k3 -> set_salt(unhexlify(bintohex(BBS().rand(64))));
        s2k3 -> set_count(96);

        // calculate the key from the passphrase
        const std::string session_key = s2k3 -> run(config.passphrase, Sym::KEY_LENGTH.at(config.sym) >> 3);

        // add checksum to secret
        secret += use_hash(Hash::SHA1, secret);

        // encrypt private key value
        primary -> set_s2k(s2k3);
        primary -> set_IV(unhexlify(bintohex(BBS().rand(Sym::BLOCK_LENGTH.at(config.sym)))));
        secret = use_normal_CFB_encrypt(config.sym, secret, session_key, primary -> get_IV());
    }
    else{
        // add checksum to secret
        uint16_t checksum = 0;
        for(uint8_t const c : secret){
            checksum += static_cast <uint16_t> (c);
        }

        secret += unhexlify(makehex(checksum, 4));
    }

    primary -> set_secret(secret);

    // first packet is primary key
    packets.push_back(primary);

    // get ID of primary key
    const std::string keyid = primary -> get_keyid();

    // generate User ID and Signature packets
    for(KeyGen::UserID const & id : config.uids){
        // User ID
        Tag13::Ptr uid = std::make_shared <Tag13> ();
        uid -> set_contents(id.user, id.comment, id.email);

        packets.push_back(uid);

        Tag2::Ptr sig = std::make_shared <Tag2> ();
        sig -> set_version(4);
        sig -> set_type(Signature_Type::POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET);
        sig -> set_pka(config.pka);
        sig -> set_hash(id.sig);

        // set creation time
        Tag2Sub2::Ptr tag2sub2 = std::make_shared <Tag2Sub2> ();
        tag2sub2 -> set_time(time);
        sig -> set_hashed_subpackets({tag2sub2});

        // set issuer
        Tag2Sub16::Ptr tag2sub16 = std::make_shared <Tag2Sub16> ();
        tag2sub16 -> set_keyid(keyid);
        sig -> set_unhashed_subpackets({tag2sub16});

        // sign Primary Key and User ID
        sig = sign_primary_key(primary, config.passphrase, primary, uid, sig, error);
        if (!sig){
            error += "Error: Failed to sign primary config.\n";
            return PGPSecretKey();
        }

        packets.push_back(sig);
    }
/*
    // generate 0 or more subkeys and associated signature packet
    for(KeyGen::SubkeyGen const & skey : config.subkeys){
        PKA::Values subkey_pub;
        PKA::Values subkey_pri;
        if (!generate_keypair(skey.pka, generate_pka_params(skey.pka, skey.bits >> 1), subkey_pri, subkey_pub)){
            error += "Error: Could not generate subkey pair.\n";
            return PGPSecretKey();
        }

        // convert the secret values into a string
        secret = "";
        for(PGPMPI const & mpi : subkey_pri){
            secret += write_MPI(mpi);
        }

        // Secret Subkey Packet
        Tag7::Ptr subkey = std::make_shared <Tag7> ();
        subkey -> set_version(4);
        subkey -> set_time(time);
        subkey -> set_pka(skey.pka);
        subkey -> set_mpi(subkey_pub);
        subkey -> set_s2k_con(0); // no passphrase up to here

        // encrypt secret only if there is a passphrase
        if (config.passphrase.size()){
            subkey -> set_s2k_con(254);
            subkey -> set_sym(skey.sym);

            // Secret Subkey S2K
            S2K3::Ptr s2k3 = std::make_shared <S2K3> ();
            s2k3 -> set_hash(skey.hash);
            s2k3 -> set_salt(unhexlify(bintohex(BBS().rand(64)))); // new salt value
            s2k3 -> set_count(96);

            // calculate the key from the passphrase
            std::string session_key = s2k3 -> run(config.passphrase, Sym::KEY_LENGTH.at(skey.sym) >> 3);

            // add checksum to secret
            secret += use_hash(Hash::SHA1, secret);

            // encrypt private key value
            subkey -> set_s2k(s2k3);
            subkey -> set_IV(unhexlify(bintohex(BBS().rand(Sym::BLOCK_LENGTH.at(skey.sym)))));
            secret = use_normal_CFB_encrypt(skey.sym, secret + use_hash(Hash::SHA1, secret), session_key, subkey -> get_IV());
        }
        else{
            // add checksum to secret
            uint16_t checksum = 0;
            for(uint8_t const c : secret){
                checksum += c;
            }

            secret += unhexlify(makehex(checksum, 4));
        }

        subkey -> set_secret(secret);

        packets.push_back(subkey);

        // Subkey Binding Signature
        Tag2::Ptr subsig = std::make_shared <Tag2> ();
        subsig -> set_version(4);
        subsig -> set_type(Signature_Type::SUBKEY_BINDING_SIGNATURE);
        subsig -> set_pka(config.pka);
        subsig -> set_hash(skey.sig);

        // set creation time
        Tag2Sub2::Ptr tag2sub2 = std::make_shared <Tag2Sub2> ();
        tag2sub2 -> set_time(time);
        subsig -> set_hashed_subpackets({tag2sub2});

        // set issuer
        Tag2Sub16::Ptr tag2sub16 = std::make_shared <Tag2Sub16> ();
        tag2sub16 -> set_keyid(keyid);
        subsig -> set_unhashed_subpackets({tag2sub16});

        // sign subkey
        subsig = sign_subkey_binding(primary, config.passphrase, subkey, subsig, error);
        if (!subsig){
            error += "Error: Subkey signing failure.\n";
            return PGPSecretKey();
        }

        packets.push_back(subsig);
    }
*/
    // put everything into a private key
    PGPSecretKey private_key;
    private_key.set_keys({std::make_pair("Version", "cc")});
    private_key.set_packets(packets);
    private_key.set_armored(true);

    // can call fill_key_sigs as well
    // return fill_key_sigs(private_key, config.passphrase, error);
    return private_key;
}

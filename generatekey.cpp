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

    for(Packet::Ptr const & p : packets){
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
                        sig = sign_primary_key(tag5, passphrase, tag5, user, sig, error);
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

                }
                else if (sig -> get_type() == Signature_Type::SUBKEY_REVOCATION_SIGNATURE){

                }
                else if (sig -> get_type() == Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE){

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

bool generate_key(KeyGen & config, PGPSecretKey & private_key, std::string & error){
    BBS(static_cast <PGPMPI> (static_cast <uint32_t> (now()))); // seed just in case not seeded

    if (!config.valid(error)){
        error += "Error: Bad key generation configuration.\n";
        return false;
    }

    // collection of packets to be put into final key
    PGP::Packets packets;

    // Key creation time
    // const time_t time = now();
    const time_t time = 1488254041;

    // generate Primary Key, User ID, and Signature packets

    // generate public key values for primary key
    PKA::Values pub;
    PKA::Values pri;
    // if (!generate_keypair(config.pka, generate_pka_params(config.pka, config.bits >> 1), pri, pub)){
        // error += "Error: Could not generate primary key pair.\n";
        // return false;
    // }

    pub = {
        hextompi("a2f705210d5cfefd4c10f83df7a55ef22736e2e88ac7aaa0be23dc13b79e61e1698d091e0db64171aa14d037393e45106249cd03f5da24e5d038d702e8895a91de1127756015d946cad0702617aec05d883dd719364a646a87337c350a62d7fd9324f7f1c9691b2fda7b1df642665b8698ab7b72e5c45d9a3d20f74c7f7f8bc8edd3b5f6173f9d428b66848b4619c38707fe07937d1d1def88971b8edb13ca22b946bd0967b61d127102a48213e992500a002568d7e9ceb6d77d125348317403d5725126953a56e97157dcf4d250b4ce1c3c0434d94882a7be356624b6b514efd999bdbdf2bfd520fa9f2a28ce560578af2999c62af209fa23051133ee516e75"),
        hextompi("010001"),
    };

    pri = {
        hextompi("1123929605ce4481063978aa27bbec2ee281eabe532e299b4b340146cf96682be94a6c6d8d3aa04a607d5ce299f21b185c85ef7a5da66a2003549f044ec9774d8501dfd8ffd87c67ee179adbdebcc1bd7481307895d5a016f60e2b9f766eabd19ee291f30b6032fc46e990de9fe01cfb1c5e5896de645705cc2d05e53539884d57f100309f49cb4a0235cf402f1bd8a61dbd89f64ca3557298ce81e71cf701583a54bce3492daa94167a5370aeadfbc273dc93b2994e2828b0d19a820600025c4f21c021ebc52c48de3da19a048971901d12a0f650f03478522908e07895372731bd0b9bb6811bb9ffe021f9b29dbc3cc383a92aa582866f1119635d199ddb41"),
        hextompi("c0c96e1ef316dc71f7a21499b14922dc8129b7e018678b1835ba98492789a10751731785c9bad5fd3d3ec03831dec56490d7f1e68aeed626a227aaf65cbdc5736e6bac4fd193225f4c53901b87a35afda564b8923e09142d762d2310ad851bde45346742d1f5dc3d3369e51333f067a40656eaa934ce464da183914199df9bd5"),
        hextompi("d86654eda6666c9f1f76e7b9edf44630a660248c4782c76afd77ecc9a70e3e74771321e1f47311ae9888bf173c53ea9937dc5179d50ef9204843d7950f2e5ca2ce76b5a3a465127aa30ebe2e78a90064ac723b33b4645a9b1761c0fd23b32168755ade989d5044bab6ce186d7a2dcc3d4c152942dbb037de5e17c226ff68f821"),
        hextompi("9f6099570d583b2467f8ba6bcc8242738f212673bec4168320cf8a3fa3ece0d3cf3ffb3ebda4369a5f4b18cc9fc846e348f6cdff67a0012ebf55fdf812859d5be4e78809733a7bfdbb6ca14ad7f5f92b1e23ec5a44f81d0134a124f9f5e4ea13ccfce3fa40470ff73f71b7b9100a0155fcccf00c183e026de35533f0fd79b758"),
    };

    // convert the secret values into a string
    std::string secret;
    for(PGPMPI const & mpi : pri){
        secret += write_MPI(mpi);
    }

    // Secret Key Packet
    Tag5::Ptr sec = std::make_shared <Tag5> ();
    sec -> set_version(4);
    sec -> set_time(time);
    sec -> set_pka(config.pka);
    sec -> set_mpi(pub);
    sec -> set_s2k_con(0); // no passphrase up to here

    // encrypt secret only if there is a passphrase
    if (config.passphrase.size()){
        sec -> set_s2k_con(254);
        sec -> set_sym(config.sym);

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
        sec -> set_s2k(s2k3);
        sec -> set_IV(unhexlify(bintohex(BBS().rand(Sym::BLOCK_LENGTH.at(config.sym)))));
        secret = use_normal_CFB_encrypt(config.sym, secret + use_hash(Hash::SHA1, secret), session_key, sec -> get_IV());
    }
    else{
        // add checksum to secret
        uint16_t checksum = 0;
        for(uint8_t const c : secret){
            checksum += c;
        }

        secret += unhexlify(makehex(checksum, 4));
    }

    sec -> set_secret(secret);

    // first packet is primary key
    packets.push_back(sec);

    // get ID of entire key
    const std::string keyid = sec -> get_keyid();

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
        // sig -> set_hashed_subpackets({tag2sub2});

        Tag2Sub27::Ptr tag2sub27 = std::make_shared <Tag2Sub27> ();
        tag2sub27 -> set_flags("\x03");

        Tag2Sub9::Ptr tag2sub9 = std::make_shared <Tag2Sub9> ();
        tag2sub9 -> set_dt(315360000);

        Tag2Sub11::Ptr tag2sub11 = std::make_shared <Tag2Sub11> ();
        tag2sub11 -> set_psa("\x09\x08\x07\x03\x02");

        Tag2Sub21::Ptr tag2sub21 = std::make_shared <Tag2Sub21> ();
        tag2sub21 -> set_pha("\x08\x02\x09\x0a\x0b");

        Tag2Sub22::Ptr tag2sub22 = std::make_shared <Tag2Sub22> ();
        tag2sub22 -> set_pca("\x02\x03\x01");

        Tag2Sub30::Ptr tag2sub30 = std::make_shared <Tag2Sub30> ();
        tag2sub30 -> set_flags("\x01");

        Tag2Sub23::Ptr tag2sub23 = std::make_shared <Tag2Sub23> ();
        tag2sub23 -> set_flags("\x80");

        sig -> set_hashed_subpackets({
            tag2sub2,
            tag2sub27,
            tag2sub9,
            tag2sub11,
            tag2sub21,
            tag2sub22,
            tag2sub30,
            tag2sub23,
        });

        // set issuer
        Tag2Sub16::Ptr tag2sub16 = std::make_shared <Tag2Sub16> ();
        tag2sub16 -> set_keyid(keyid);
        sig -> set_unhashed_subpackets({tag2sub16});

        // sign Primary Key and User ID
        sig = sign_primary_key(sec, config.passphrase, sec, uid, sig, error);
        if (!sig){
            error += "Error: Failed to sign primary config.\n";
            return false;
        }

        packets.push_back(sig);
    }

    // generate 0 or more subkeys and associated signature packet
    for(KeyGen::SubkeyGen const & skey : config.subkeys){
        PKA::Values subkey_pub;
        PKA::Values subkey_pri;
        // if (!generate_keypair(skey.pka, generate_pka_params(skey.pka, skey.bits >> 1), subkey_pri, subkey_pub)){
            // error += "Error: Could not generate subkey pair.\n";
            // return false;
        // }

        subkey_pub = {
            hextompi("ba2b550b1c167afc8fcb8534013c15fca0efc9de8a981f9d3f0a8ec480fe4a978bd35887c75f3df724810980e234f85e2ec9fe2d29643240e9da678bf6f6ef89baa3853c46cad1d5f19cd4f7854f4c94010a7abe4dbc3581e996a2cd80b8d77f94db0758893854adf76c3df1ffdc0168f571127919d6b4fb4aa8dc070eefbe1152f5fecaf1db57142851a76ebd113b20ba93ca497a8c5f82647d9fff5f00490ab096420ede08a42fed40e4088fb62657dd3721723a3d414adc7378b273ed54591d54234f3b691c626bf2937b6c6d98446a962bbf5339ce09997ff27f7639eacb65871c04dcc3f8732bf387dc3d97d067a918d9f826ea30ac4900d164d264f7b9"),
            hextompi("010001"),
        };

        subkey_pri = {
            hextompi("1237860476a8c4fb548346db20414dc9f90209c3f8d61aa6d789bc0f62ab6f675d9f6e46e8058bf1d46cbb7e34f457b6d8977ba395eca7e5b5f461043f43e9cbd57b6580d0d10d20251ab274af82e3548ab708ac793d10d3cfe48574fc32ea2461ef9e4c05ae614bde1d8580ba07804c51d3110a9052940650678e5332fd16e11e90d68cbc1a9af7f715a585d9a26f24081f68770b238a0dd1a7bfab567ae2a40dd5c42c713b8090dadccf820bfeeb71019c8edb20f45916f580f3ea6a328158b05c66a613736c2105b0e611fd55a55f0aaa8986514e6f74d44af6af20a0c0f6fe4b2a222da0d0a15d3dc196f231aeda34db82c34d39c0eb58d1aa266bf7f7d1"),
            hextompi("cfac9c4a4e3039bc5b8f0fc1dd0782af0f4e3dc6b10d33c6f69a6201765dc985089f8b85d88d650031d7a14fe2063f3bd5d653b44843ad42f545c0e099e43826ac2cb5b30b5354ff0702ec33b8f6bfdc0f8a5e834101fe56d1b691c8a4684e7b27933c15364f6bed956a4773b64a6c330efaef200293cb9aa121d56732d0b789"),
            hextompi("e57da520246e47734ff77a0f5c58b5e7ce4b2b474714aff4f1f6d987cce442d10f752c5c2020036ff73966ef2b2f9d058084518b5ac52082cfe24c494e8f32da8ba837fbe19f7bd000c40cfade912ddbb50456cdbff69f38658ae4f82cf71624baace7caa777efcf56fd399d28038b0ab1642fa9d2121dc9d0d4033cd8af02b1"),
            hextompi("b7221f9f80da498d791c92fced5b0622ef1f4d0c47e6a2667f173809d9b9ed08509a9d4ed0bd48705d673580d9c8ed4c30d04b4b812f0d0699952efeb1570a58bee11c5abafcc01efa29e9c64d2d49cac82f6dc7578a26c050d1adab9b4d6b26855d26043f1258cab9c6c4560db14bfe2606377f514bd927af321fd1224740fc"),
        };

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
        // subsig -> set_hashed_subpackets({tag2sub2});

        Tag2Sub27::Ptr tag2sub27 = std::make_shared <Tag2Sub27> ();
        tag2sub27 -> set_flags("\x0c");

        Tag2Sub9::Ptr tag2sub9 = std::make_shared <Tag2Sub9> ();
        tag2sub9 -> set_dt(315360000);

        subsig -> set_hashed_subpackets({
            tag2sub2,
            tag2sub27,
            tag2sub9,
        });

        // set issuer
        Tag2Sub16::Ptr tag2sub16 = std::make_shared <Tag2Sub16> ();
        tag2sub16 -> set_keyid(keyid);
        subsig -> set_unhashed_subpackets({tag2sub16});

        // sign subkey
        subsig = sign_subkey_binding(sec, config.passphrase, subkey, subsig, error);
        if (!subsig){
            error += "Error: Subkey signing failure.\n";
            return false;
        }

        packets.push_back(subsig);
    }

    // put everything into a private key
    private_key.set_type(PGP::PRIVATE_KEY_BLOCK);
    private_key.set_keys({std::make_pair("Version", "cc")});
    private_key.set_packets(packets);
    private_key.set_armored(true);

    return true;
}

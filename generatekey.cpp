#include "generatekey.h"

bool generate_keys(const KeyGen & key, PGPPublicKey & public_key, PGPSecretKey & private_key, std::string & error){
    BBS(static_cast <PGPMPI> (static_cast <uint32_t> (now()))); // seed just in case not seeded

    if (!key.valid(error)){
        error += "Error: Bad key generation configuration.\n";
        return false;
    }

    // collection of packets to be put into final key
    PGP::Packets packets;

    // Key creation time
    const time_t time = now();

    // generate Primary Key, User ID, and Signature packets

    // generate public key values for primary key
    PKA::Values pub;
    PKA::Values pri;
    if (!generate_keypair(key.pka, generate_pka_params(key.pka, key.bits), pri, pub)){
        error += "Error: Could not generate primary key pair.\n";
        return false;
    }

    // convert the secret values into a string
    std::string secret;
    for(PGPMPI const & mpi : pri){
        secret += write_MPI(mpi);
    }

    // Secret Key Packet
    Tag5::Ptr sec = std::make_shared <Tag5> ();
    sec -> set_version(4);
    sec -> set_time(time);
    sec -> set_pka(key.pka);
    sec -> set_mpi(pub);
    sec -> set_s2k_con(0); // no passphrase up to here

    // encrypt secret only if there is a passphrase
    if (key.passphrase.size()){
        sec -> set_s2k_con(254);
        sec -> set_sym(key.sym);

        // Secret Key Packet S2K
        S2K3::Ptr s2k3 = std::make_shared <S2K3> ();
        s2k3 -> set_hash(key.hash);
        s2k3 -> set_salt(unhexlify(bintohex(BBS().rand(64))));
        s2k3 -> set_count(96);

        // calculate the key from the passphrase
        const std::string session_key = s2k3 -> run(key.passphrase, Sym::KEY_LENGTH.at(key.sym) >> 3);

        // add checksum to secret
        secret += use_hash(Hash::SHA1, secret);

        // encrypt private key value
        sec -> set_s2k(s2k3);
        sec -> set_IV(unhexlify(bintohex(BBS().rand(Sym::BLOCK_LENGTH.at(key.sym)))));
        secret = use_normal_CFB_encrypt(key.sym, secret + use_hash(Hash::SHA1, secret), session_key, sec -> get_IV());
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
    for(KeyGen::UserID const & id : key.uids){
        // User ID
        Tag13::Ptr uid = std::make_shared <Tag13> ();
        uid -> set_contents(id.user, id.comment, id.email);

        packets.push_back(uid);

        Tag2::Ptr sig = std::make_shared <Tag2> ();
        sig -> set_version(4);
        sig -> set_type(Signature_Type::POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET);
        sig -> set_pka(key.pka);
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
        const std::string sig_hash = to_sign_13(sec, uid, sig);
        sig -> set_left16(sig_hash.substr(0, 2));
        sig -> set_mpi(pka_sign(sig_hash, key.pka, pri, pub, id.sig, error));

        packets.push_back(sig);
    }

    // generate 0 or more subkeys and associated signature packet
    for(KeyGen::SubkeyGen const & skey : key.subkeys){
        PKA::Values subkey_pub;
        PKA::Values subkey_pri;
        if (!generate_keypair(skey.pka, generate_pka_params(skey.pka, skey.bits), subkey_pri, subkey_pub)){
            error += "Error: Could not generate subkey pair.\n";
            return false;
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
        if (key.passphrase.size()){
            subkey -> set_s2k_con(254);
            subkey -> set_sym(skey.sym);

            // Secret Subkey S2K
            S2K3::Ptr s2k3 = std::make_shared <S2K3> ();
            s2k3 -> set_hash(skey.hash);
            s2k3 -> set_salt(unhexlify(bintohex(BBS().rand(64)))); // new salt value
            s2k3 -> set_count(96);

            // calculate the key from the passphrase
            std::string session_key = s2k3 -> run(key.passphrase, Sym::KEY_LENGTH.at(skey.sym) >> 3);

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
        subsig -> set_pka(key.pka);
        subsig -> set_hash(skey.sig);

        // set creation time
        Tag2Sub2::Ptr tag2sub2 = std::make_shared <Tag2Sub2> ();
        tag2sub2 -> set_time(time);
        subsig -> set_hashed_subpackets({tag2sub2});

        // set issuer
        Tag2Sub16::Ptr tag2sub16 = std::make_shared <Tag2Sub16> ();
        tag2sub16 -> set_keyid(keyid);
        subsig -> set_unhashed_subpackets({tag2sub16});

        // sign
        const std::string sig_hash = to_sign_18(sec, subkey, subsig);
        subsig -> set_left16(sig_hash.substr(0, 2));
        subsig -> set_mpi(pka_sign(sig_hash, key.pka, pri, pub, skey.sig, error));

        packets.push_back(subsig);
    }

    // put everything into a private key
    private_key.set_type(PGP::PRIVATE_KEY_BLOCK);
    private_key.set_keys({std::make_pair("Version", "cc")});
    private_key.set_packets(packets);
    private_key.set_armored(true);

    // extract public key from private key
    public_key = private_key.get_public();

    return true;
}

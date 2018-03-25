#include "keygen.h"

namespace OpenPGP {
namespace KeyGen {

bool fill_key_sigs(SecretKey & private_key, const std::string & passphrase){
    RNG::BBS(static_cast <MPI> (static_cast <uint32_t> (now()))); // seed just in case not seeded

    if (!private_key.meaningful()){
        // "Error: Bad key.\n";
        return false;
    }

    const std::string keyid = private_key.keyid();
    const Packet::Tag5::Ptr primary = std::static_pointer_cast <Packet::Tag5> (private_key.get_packets()[0]);
    PGP::Packets packets = private_key.get_packets_clone();

    Packet::Key::Ptr key = nullptr;
    Packet::User::Ptr user = nullptr;

    for(Packet::Tag::Ptr & p : packets){
        if (Packet::is_key_packet(p -> get_tag())){
            key = std::static_pointer_cast <Packet::Key> (p);
            user = nullptr;
        }
        else if (Packet::is_user(p -> get_tag())){
            user = std::static_pointer_cast <Packet::User> (p);
        }
        else if (p -> get_tag() == Packet::SIGNATURE){
            Packet::Tag2::Ptr sig = std::static_pointer_cast <Packet::Tag2> (p);

            // only fill in keys that are supposed to be signed by the primary key
            // don't fill in empty key IDs
            if (sig -> get_keyid() == keyid){
                if (Signature_Type::is_certification(sig -> get_type())){
                    if (key -> get_tag() == Packet::SECRET_KEY){
                        const Packet::Tag5::Ptr tag5 = std::static_pointer_cast <Packet::Tag5> (key);
                        sig = Sign::primary_key(primary, passphrase, tag5, user, sig);
                    }
                    else{
                        // "Error: Certification signature attempted to be made for a non-primary key.\n";
                        return false;
                    }
                }
                else if (sig -> get_type() == Signature_Type::SUBKEY_BINDING_SIGNATURE){
                    if (key -> get_tag() == Packet::SECRET_SUBKEY){
                        const Packet::Tag7::Ptr tag7 = std::static_pointer_cast <Packet::Tag7> (key);
                        sig = Sign::subkey_binding(primary, passphrase, tag7, sig);
                    }
                    else{
                        // "Error: Subkey Binding signature attempted to be made for a non-subkey.\n";
                        return false;
                    }
                }
                else if (sig -> get_type() == Signature_Type::KEY_REVOCATION_SIGNATURE){
                    sig = Revoke::sig(primary, passphrase, primary, sig);
                }
                else if (sig -> get_type() == Signature_Type::SUBKEY_REVOCATION_SIGNATURE){
                    sig = Revoke::sig(primary, passphrase, key, sig);
                }
                else if (sig -> get_type() == Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE){
                    sig = Revoke::uid_sig(primary, passphrase, user, sig);
                }
                else{
                    std::cerr << "Warning: Bad or unhandled signature type: 0x" << makehex(sig -> get_type(), 2) << std::endl;
                }
            }
        }
        else{
            // should never come here
            // "Error: Random packet found.\n";
            return false;
        }
    }

    private_key.set_packets(packets);

    return true;
}

SecretKey generate_key(Config & config){
    RNG::BBS(static_cast <MPI> (static_cast <uint32_t> (now()))); // seed just in case not seeded

    if (!config.valid()){
        // "Error: Bad key generation configuration.\n";
        return SecretKey();
    }

    // collection of packets to be put into final key
    PGP::Packets packets;

    // Key creation time
    const uint32_t time = now();

    // generate Primary Key, User ID, and Signature packets

    // generate public key values for primary key
    PKA::Values pub;
    PKA::Values pri;
    if (!PKA::generate_keypair(config.pka, PKA::generate_params(config.pka, config.bits >> 1), pri, pub)){
        // "Error: Could not generate primary key pair.\n";
        return SecretKey();
    }

    // convert the secret values into a string
    std::string secret;
    for(MPI const & mpi : pri){
        secret += write_MPI(mpi);
    }

    // Secret Key Packet
    Packet::Tag5::Ptr primary = std::make_shared <Packet::Tag5> ();
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
        S2K::S2K3::Ptr s2k3 = std::make_shared <S2K::S2K3> ();
        s2k3 -> set_hash(config.hash);
        s2k3 -> set_salt(unhexlify(bintohex(RNG::BBS().rand(64))));
        s2k3 -> set_count(96);

        // calculate the key from the passphrase
        const std::string session_key = s2k3 -> run(config.passphrase, Sym::KEY_LENGTH.at(config.sym) >> 3);

        // add checksum to secret
        secret += Hash::use(Hash::ID::SHA1, secret);

        // encrypt private key value
        primary -> set_s2k(s2k3);
        primary -> set_IV(unhexlify(bintohex(RNG::BBS().rand(Sym::BLOCK_LENGTH.at(config.sym)))));
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
    for(Config::UserID const & id : config.uids){
        // User ID
        Packet::Tag13::Ptr uid = std::make_shared <Packet::Tag13> ();
        uid -> set_contents(id.user, id.comment, id.email);

        packets.push_back(uid);

        Packet::Tag2::Ptr sig = std::make_shared <Packet::Tag2> ();
        sig -> set_version(4);
        sig -> set_type(Signature_Type::POSITIVE_CERTIFICATION_OF_A_USER_ID_AND_PUBLIC_KEY_PACKET);
        sig -> set_pka(config.pka);
        sig -> set_hash(id.sig);

        // set creation time
        Subpacket::Tag2::Sub2::Ptr tag2sub2 = std::make_shared <Subpacket::Tag2::Sub2> ();
        tag2sub2 -> set_time(time);
        sig -> set_hashed_subpackets({tag2sub2});

        // set issuer
        Subpacket::Tag2::Sub16::Ptr tag2sub16 = std::make_shared <Subpacket::Tag2::Sub16> ();
        tag2sub16 -> set_keyid(keyid);
        sig -> set_unhashed_subpackets({tag2sub16});

        // sign Primary Key and User ID
        sig = Sign::primary_key(primary, config.passphrase, primary, uid, sig);
        if (!sig){
            // "Error: Failed to sign primary config.\n";
            return SecretKey();
        }

        packets.push_back(sig);
    }

    // generate 0 or more subkeys and associated signature packet
    for(Config::SubkeyGen const & skey : config.subkeys){
        PKA::Values subkey_pub;
        PKA::Values subkey_pri;
        if (!PKA::generate_keypair(skey.pka, PKA::generate_params(skey.pka, skey.bits >> 1), subkey_pri, subkey_pub)){
            // "Error: Could not generate subkey pair.\n";
            return SecretKey();
        }

        // convert the secret values into a string
        secret = "";
        for(MPI const & mpi : subkey_pri){
            secret += write_MPI(mpi);
        }

        // Secret Subkey Packet
        Packet::Tag7::Ptr subkey = std::make_shared <Packet::Tag7> ();
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
            S2K::S2K3::Ptr s2k3 = std::make_shared <S2K::S2K3> ();
            s2k3 -> set_hash(skey.hash);
            s2k3 -> set_salt(unhexlify(bintohex(RNG::BBS().rand(64)))); // new salt value
            s2k3 -> set_count(96);

            // calculate the key from the passphrase
            std::string session_key = s2k3 -> run(config.passphrase, Sym::KEY_LENGTH.at(skey.sym) >> 3);

            // add checksum to secret
            secret += Hash::use(Hash::ID::SHA1, secret);

            // encrypt private key value
            subkey -> set_s2k(s2k3);
            subkey -> set_IV(unhexlify(bintohex(RNG::BBS().rand(Sym::BLOCK_LENGTH.at(skey.sym)))));
            secret = use_normal_CFB_encrypt(skey.sym, secret + Hash::use(Hash::ID::SHA1, secret), session_key, subkey -> get_IV());
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
        Packet::Tag2::Ptr subsig = std::make_shared <Packet::Tag2> ();
        subsig -> set_version(4);
        subsig -> set_type(Signature_Type::SUBKEY_BINDING_SIGNATURE);
        subsig -> set_pka(config.pka);
        subsig -> set_hash(skey.sig);

        // set creation time
        Subpacket::Tag2::Sub2::Ptr tag2sub2 = std::make_shared <Subpacket::Tag2::Sub2> ();
        tag2sub2 -> set_time(time);
        subsig -> set_hashed_subpackets({tag2sub2});

        // set issuer
        Subpacket::Tag2::Sub16::Ptr tag2sub16 = std::make_shared <Subpacket::Tag2::Sub16> ();
        tag2sub16 -> set_keyid(keyid);
        subsig -> set_unhashed_subpackets({tag2sub16});

        // sign subkey
        subsig = Sign::subkey_binding(primary, config.passphrase, subkey, subsig);
        if (!subsig){
            // "Error: Subkey signing failure.\n";
            return SecretKey();
        }

        packets.push_back(subsig);
    }

    // put everything into a private key
    SecretKey private_key;
    private_key.set_keys({std::make_pair("Version", "cc")});
    private_key.set_packets(packets);
    private_key.set_armored(true);

    // can call fill_key_sigs as well
    // return fill_key_sigs(private_key, config.passphrase);
    return private_key;
}

}
}

#include "encrypt.h"

namespace OpenPGP {
namespace Encrypt {

Packet::Tag::Ptr data(const Args & args,
                 const std::string & session_key){

    if (!args.valid()){
        // "Error: Bad argument.\n";
        return nullptr;
    }

    std::string to_encrypt;

    // if message is to be signed
    if (args.signer){
        const Sign::Args signargs(*(args.signer), args.passphrase, 4, args.hash);
        Message signed_message = Sign::binary(signargs, args.filename, args.data, args.comp);
        if (!signed_message.meaningful()){
            // "Error: Signing failure.\n";
            return nullptr;
        }

        to_encrypt = signed_message.raw();
    }
    else{
        // put data in Literal Data Packet
        Packet::Tag11 tag11;
        tag11.set_format('b');
        tag11.set_filename(args.filename);
        tag11.set_time(0);
        tag11.set_literal(args.data);

        to_encrypt = tag11.write(Packet::Tag::Format::NEW);

        if (args.comp){
            // Compressed Data Packet (Tag 8)
            Packet::Tag8 tag8;
            tag8.set_comp(args.comp);
            tag8.set_data(to_encrypt); // put source data into compressed packet
            to_encrypt = tag8.write(Packet::Tag::Format::NEW);
        }
    }

    // generate prefix
    const std::size_t BS = Sym::BLOCK_LENGTH.at(args.sym);
    std::string prefix = unbinify(RNG::BBS().rand(BS));
    prefix += prefix.substr(prefix.size() - 2, 2);

    Packet::Tag::Ptr encrypted = nullptr;

    if (!args.mdc){
        // Symmetrically Encrypted Data Packet (Tag 9)
        Packet::Tag9 tag9;
        tag9.set_encrypted_data(use_OpenPGP_CFB_encrypt(args.sym, Packet::SYMMETRICALLY_ENCRYPTED_DATA, to_encrypt, session_key, prefix));
        encrypted = std::make_shared <Packet::Tag9> (tag9);
    }
    else{
        // Modification Detection Code Packet (Tag 19)
        Packet::Tag19 tag19;
        tag19.set_hash(Hash::use(Hash::ID::SHA1, prefix + to_encrypt + "\xd3\x14"));

        // Sym. Encrypted Integrity Protected Data Packet (Tag 18)
        // encrypt(compressed(literal_data_packet(plain text)) + MDC SHA1(20 octets))
        Packet::Tag18 tag18;
        tag18.set_protected_data(use_OpenPGP_CFB_encrypt(args.sym, Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA, to_encrypt + tag19.write(), session_key, prefix));
        encrypted = std::make_shared <Packet::Tag18> (tag18);
    }

    return encrypted;
}

Message pka(const Args & args,
            const Key & pgpkey){
    RNG::BBS(static_cast <MPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded

    if (!args.valid()){
        // "Error: Bad argument.\n";
        return Message();
    }

    if (!pgpkey.meaningful()){
        // "Error: Bad key.\n";
        return Message();
    }

    // Check if key has been revoked
    const int rc = Revoke::check(pgpkey);
    if (rc == true){
        // "Error: Key " + hexlify(pgpkey.keyid()) + " has been revoked. Nothing done.\n";
        return Message();
    }
    else if (rc == -1){
        // "Error: check_revoked failed.\n";
        return Message();
    }

    Packet::Key::Ptr key = nullptr;
    for(Packet::Tag::Ptr const & p : pgpkey.get_packets()){
        key = nullptr;
        if (Packet::is_key_packet(p -> get_tag())){
            key = std::static_pointer_cast <Packet::Key> (p);

            // make sure key has encrypting keys
            if (PKA::can_encrypt(key -> get_pka())){
                break;
            }
        }
    }

    if (!key){
        // "Error: No encrypting key found.\n";
        return Message();
    }

    PKA::Values mpi = key -> get_mpi();
    Packet::Tag1::Ptr tag1 = std::make_shared <Packet::Tag1> ();
    tag1 -> set_keyid(key -> get_keyid());
    tag1 -> set_pka(key -> get_pka());

    // do calculations

    // generate session key
    const std::size_t key_len = Sym::KEY_LENGTH.at(args.sym);
    const std::string session_key = unbinify(RNG::BBS().rand(key_len));

    // get checksum of session key
    uint16_t sum = 0;
    for(char const c : session_key){
        sum += static_cast <unsigned char> (c);
    }

    std::string nibbles = mpitohex(mpi[0]);        // get hex representation of modulus
    nibbles += std::string(nibbles.size() & 1, 0); // get even number of nibbles
    MPI m = hextompi(hexlify(EME_PKCS1v1_5_ENCODE(std::string(1, args.sym) + session_key + unhexlify(makehex(sum, 4)), nibbles.size() >> 1)));

    // encrypt m
    if ((key -> get_pka() == PKA::ID::RSA_ENCRYPT_OR_SIGN) ||
        (key -> get_pka() == PKA::ID::RSA_ENCRYPT_ONLY)){
        tag1 -> set_mpi({PKA::RSA::encrypt(m, mpi)});
    }
    else if (key -> get_pka() == PKA::ID::ELGAMAL){
        tag1 -> set_mpi(PKA::ElGamal::encrypt(m, mpi));
    }

    // encrypt data and put it into a packet
    Packet::Tag::Ptr encrypted = data(args, session_key);
    if (!encrypted){
        // "Error: Failed to encrypt data.\n";
        return Message();
    }

    // write data to output container
    Message out;
    out.set_keys({std::make_pair("Version", "cc")});
    out.set_packets({tag1, encrypted});

    return out;
}

Message sym(const Args & args,
            const std::string & passphrase,
            const uint8_t key_hash){
    RNG::BBS(static_cast <MPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded

    if (!args.valid()){
        // "Error: Bad argument.\n";
        return Message();
    }

    // String to Key specifier for decrypting session key
    S2K::S2K3::Ptr s2k = std::make_shared <S2K::S2K3> ();
    s2k -> set_type(S2K::ID::ITERATED_AND_SALTED_S2K);
    s2k -> set_hash(key_hash);
    s2k -> set_salt(unbinify(RNG::BBS().rand(64)));
    s2k -> set_count(96);

    // generate Symmetric-Key Encrypted Session Key Packets (Tag 3)
    Packet::Tag3::Ptr tag3 = std::make_shared <Packet::Tag3> ();
    tag3 -> set_version(4);
    tag3 -> set_sym(args.sym);
    tag3 -> set_s2k(s2k);

    // generate session key
    const std::string session_key = tag3 -> get_session_key(passphrase);

    // encrypt data
    Packet::Tag::Ptr encrypted = data(args, session_key.substr(1, session_key.size() - 1));
    if (!encrypted){
        // "Error: Failed to encrypt data.\n";
        return Message();
    }

    // write to output container
    Message out;
    out.set_keys({std::make_pair("Version", "cc")});
    out.set_packets({tag3, encrypted});

    return out;
}

}
}
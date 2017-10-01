#include "decrypt.h"

namespace OpenPGP {
namespace Decrypt {

Message data(const uint8_t sym,
             const Message & message,
             const std::string & session_key){
    if (!message.meaningful()){
        // "Error: Bad message.\n";
        return Message();
    }

    // find start of encrypted data
    PGP::Packets::size_type i = 0;
    PGP::Packets packets = message.get_packets();
    while ((i < packets.size()) && !Packet::is_sym_protected_data(packets[i] -> get_tag())){
        i++;
    }

    if (i == packets.size()){
        // "Error: No encrypted data found.\n";
        return Message();
    }

    uint8_t tag;
    std::string data = "";

    // copy initial data to string
    if (packets[i] -> get_tag() == Packet::SYMMETRICALLY_ENCRYPTED_DATA){
        data = std::static_pointer_cast <Packet::Tag9> (packets[i]) -> get_encrypted_data();
        tag = Packet::SYMMETRICALLY_ENCRYPTED_DATA;
    }
    else if (packets[i] -> get_tag() == Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA){
        data = std::static_pointer_cast <Packet::Tag18> (packets[i]) -> get_protected_data();
        tag = Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA;
    }

    if (!data.size()){
        // "Error: No encrypted data packet(s) found.\n";
        return Message();
    }

    // decrypt data
    data = use_OpenPGP_CFB_decrypt(sym, tag, data, session_key);

    // get blocksize of symmetric key algorithm
    const unsigned int BS = Sym::BLOCK_LENGTH.at(sym) >> 3;

    // strip extra data
    if (tag == Packet::SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA){
        const std::string checksum = data.substr(data.size() - 20, 20); // get given SHA1 checksum
        data = data.substr(0, data.size() - 20);                        // remove SHA1 checksum
        if (Hash::use(Hash::ID::SHA1, data) != checksum){                    // check SHA1 checksum
            // "Error: Given checksum and calculated checksum do not match.";
            return Message();
        }

        data = data.substr(0, data.size() - 2);                         // get rid of \xd3\x14
    }

    data = data.substr(BS + 2, data.size() - BS - 2);                   // get rid of prefix

    // decompress and parse decrypted data
    return Message(data);
}

Message pka(const SecretKey & pri,
            const std::string & passphrase,
            const Message & message){
    if (!pri.meaningful()){
        // "Error: Bad private key.\n";
        return Message();
    }

    if (!message.meaningful()){
        // "Error: No encrypted message found.\n";
        return Message();
    }

    // find Public-Key Encrypted Session Key Packet (Tag 1)
    // should be first packet
    Packet::Tag1::Ptr tag1 = nullptr;
    for(Packet::Tag::Ptr const & p : message.get_packets()){
        if (p -> get_tag() == Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY){
            tag1 = std::static_pointer_cast <Packet::Tag1> (p);
            break;
        }
    }

    if (!tag1){
        // "Error: No " + Packet::NAME.at(Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY) + " (Tag " + std::to_string(Packet::PUBLIC_KEY_ENCRYPTED_SESSION_KEY) + ") found.\n";
        return Message();
    }

    if (!PKA::can_encrypt(tag1 -> get_pka())){
        // "Error: Public Key Algorithm detected cannot be used to encrypt/decrypt.\n";
        return Message();
    }

    // find corresponding secret key
    Packet::Tag5::Ptr sec = nullptr;
    for(Packet::Tag::Ptr const & p : pri.get_packets()){
        sec = nullptr;
        if (Packet::is_secret(p -> get_tag())){
            sec = std::static_pointer_cast <Packet::Tag5> (p);
            // encrypted packet Key ID has to match decrypting Key ID, not main Key ID
            if (sec -> get_public_ptr() -> get_keyid() != tag1 -> get_keyid()){
                continue;
            }

            // make sure key has encrypting keys
            if (PKA::can_encrypt(sec -> get_pka())){
                break;
            }
        }
    }

    if (!sec){
        // "Error: Correct Private Key not found.\n";
        return Message();
    }

    // decrypt secret keys
    std::string symkey;
    if ((tag1 -> get_pka() == PKA::ID::RSA_ENCRYPT_OR_SIGN) ||
        (tag1 -> get_pka() == PKA::ID::RSA_ENCRYPT_ONLY)){
        symkey = mpitoraw(PKA::RSA::decrypt(tag1 -> get_mpi()[0], sec -> decrypt_secret_keys(passphrase), sec -> get_mpi()));
    }
    else if (tag1 -> get_pka() == PKA::ID::ELGAMAL){
        symkey = PKA::ElGamal::decrypt(tag1 -> get_mpi(), sec -> decrypt_secret_keys(passphrase), sec -> get_mpi());
    }

    // get symmetric algorithm, session key, 2 octet checksum wrapped in EME_PKCS1_ENCODE
    symkey = zero + symkey;

    if (!(symkey = EME_PKCS1v1_5_DECODE(symkey)).size()){            // remove EME_PKCS1 encoding
        // "Error: EME_PKCS1v1_5_DECODE failure.\n";
        return Message();
    }

    const uint8_t sym = symkey[0];                                          // get symmetric algorithm
    const std::string checksum = symkey.substr(symkey.size() - 2, 2);       // get 2 octet checksum
    symkey = symkey.substr(1, symkey.size() - 3);                           // remove both from session key

    uint16_t sum = 0;
    for(char & c : symkey){                                                 // calculate session key checksum
        sum += static_cast <uint8_t> (c);
    }

    if (unhexlify(makehex(sum, 4)) != checksum){                            // check session key checksums
        // "Error: Calculated session key checksum does not match given checksum.\n";
        return Message();
    }

    // decrypt the data with the extracted key
    return data(sym, message, symkey);
}

Message sym(const Message & message,
            const std::string & passphrase){
    if (!message.meaningful()){
        // "Error: Bad message.\n";
        return Message();
    }

    // find Symmetric Key Encrypted Session Key (Tag 3)
    // should be first packet
    Packet::Tag3::Ptr tag3 = nullptr;
    for(Packet::Tag::Ptr const & p : message.get_packets()){
        if (p -> get_tag() == Packet::SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY){
            tag3 = std::static_pointer_cast <Packet::Tag3> (p);
            break;
        }
    }

    if (!tag3){
        // "Error: No " + Packet::NAME.at(Packet::SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY) + " (Tag " + std::to_string(Packet::SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY) + ") found.\n";
        return Message();
    }

    const std::string symkey = tag3 -> get_session_key(passphrase);
    return data(symkey[0], message, symkey.substr(1, symkey.size() - 1));
}

}
}
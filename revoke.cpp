#include "revoke.h"

Tag2 * revoke_primary_key_cert(PGP & pri, const std::string & passphrase, const uint8_t code, const std::string & reason){
    if (pri.get_ASCII_Armor() != 2){
        std::cerr << "Error: A private key is required for the second argument." << std::endl;
        exit(1);
    }

    Tag5 * signer = find_signing_key(pri);

    Tag5 * key = NULL;
    std::vector <Packet *> packets = pri.get_packets();
    for(Packet *& p : packets){
        if (p -> get_tag() == 5){
            std::string data = p -> raw();
            key = new Tag5(data);
            break;
        }
    }

    if (!key){
        std::cerr << "Error: No Secret Key packet found." << std::endl;
        exit(1);
    }

    Tag2 * sig = create_sig_packet(0x20, signer);

    std::vector <Subpacket *> hashed_subpackets = sig -> get_hashed_subpackets_clone();
    Tag2Sub29 * revoke = new Tag2Sub29;
    revoke -> set_code(code);
    revoke -> set_reason(reason);
    hashed_subpackets.push_back(revoke);
    sig -> set_hashed_subpackets(hashed_subpackets);

    std::string hashed_data = to_sign_20(key, sig);
    sig -> set_left16(hashed_data.substr(0, 2));
    sig -> set_mpi(pka_sign(hashed_data, signer, passphrase, sig -> get_hash()));

    delete signer;
    delete key;

    return sig;
}

PGP revoke_primary_key_cert_key(PGP & pri, const std::string & passphrase, const uint8_t code, const std::string & reason){
    Tag2 * sig = revoke_primary_key_cert(pri, passphrase, code, reason);

    PGP signature;
    signature.set_ASCII_Armor(1);
    std::vector <std::pair <std::string, std::string> > h = {std::make_pair("Version", "cc"),
                                                             std::make_pair("Comment", "Revocation Certificate")};
    signature.set_Armor_Header(h);
    signature.set_packets({sig});

    delete sig;

    return signature;
}

Tag2 * revoke_subkey_cert(PGP & pri, const std::string & passphrase, const uint8_t code, const std::string & reason){
    if (pri.get_ASCII_Armor() != 2){
        std::cerr << "Error: A private key is required for the second argument." << std::endl;
        exit(1);
    }

    Tag5 * signer = find_signing_key(pri);

    Tag7 * key = NULL;
    std::vector <Packet *> packets = pri.get_packets();
    for(Packet *& p : packets){
        if (p -> get_tag() == 7){
            std::string data = p -> raw();
            key = new Tag7(data);
            break;
        }
    }

    if (!key){
        std::cerr << "Error: No Secret Subkey packet found." << std::endl;
        exit(1);
    }

    Tag2 * sig = create_sig_packet(0x28, signer);

    std::vector <Subpacket *> hashed_subpackets = sig -> get_hashed_subpackets_clone();
    Tag2Sub29 * revoke = new Tag2Sub29;
    revoke -> set_code(code);
    revoke -> set_reason(reason);
    hashed_subpackets.push_back(revoke);
    sig -> set_hashed_subpackets(hashed_subpackets);

    std::string hashed_data = to_sign_28(key, sig);
    sig -> set_left16(hashed_data.substr(0, 2));
    sig -> set_mpi(pka_sign(hashed_data, signer, passphrase, sig -> get_hash()));

    delete signer;
    delete key;

    return sig;
}

PGP revoke_subkey_cert_key(PGP & pri, const std::string & passphrase, const uint8_t code, const std::string & reason){
    Tag2 * sig = revoke_subkey_cert(pri, passphrase, code, reason);

    PGP signature;
    signature.set_ASCII_Armor(1);
    std::vector <std::pair <std::string, std::string> > h = {std::make_pair("Version", "cc"),
                                                             std::make_pair("Comment", "Revocation Certificate")};
    signature.set_Armor_Header(h);
    signature.set_packets({sig});

    return signature;
}

PGP revoke_key(PGP & pri, const std::string & passphrase, const uint8_t code, const std::string & reason){
    std::vector <Packet *> packets = pri.get_packets();

    Tag2 * rev = revoke_primary_key_cert(pri, passphrase, code, reason);

    std::string data = packets[0] -> raw();
    Tag6 * primary = new Tag6(data);

    // assume first packet is primary key, and add a revocation signature as the next packet
    std::vector <Packet *> new_packets = {primary, rev};
    // clone the rest of the packets
    for(unsigned int i = 1; i < packets.size(); i++){
        new_packets.push_back(packets[i] -> clone());
    }

    PGP revoked;
    revoked.set_ASCII_Armor(1); // public key
    revoked.set_Armor_Header(pri.get_Armor_Header());
    revoked.set_packets(new_packets);

    for(Packet *& p : new_packets){
        delete p;
    }

    return revoked;
}

PGP revoke_subkey(PGP & pri, const std::string & passphrase, const uint8_t code, const std::string & reason){
    std::vector <Packet *> packets = pri.get_packets();

    Tag2 * rev = revoke_subkey_cert(pri, passphrase, code, reason);

    // assume first packet is primary key
    std::vector <Packet *> new_packets;

    // clone all packets up to and including the subkey
    unsigned int i = 0;
    do{
        new_packets.push_back(packets[i] -> clone());
    }
    while (packets[i++] -> get_tag() != 7);

    // append the revocation key
    new_packets.push_back(rev);

    // clone the rest of the key
    while (i < packets.size()){
        new_packets.push_back(packets[i++] -> clone());
    }

    PGP revoked;
    revoked.set_ASCII_Armor(1); // public key
    revoked.set_Armor_Header(pri.get_Armor_Header());
    revoked.set_packets(new_packets);

    for(Packet *& p : new_packets){
        delete p;
    }

    return revoked;
}

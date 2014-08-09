#include "PGPKey.h"

bool PGPKey::meaningful(uint8_t type) const{
    uint8_t key, subkey;

    if (type == 1){ // Public Key
        key = 6;
        subkey = 14;
    }
    if (type == 2){ // Private Key
        key = 5;
        subkey = 7;
    }

    unsigned int packet_count = packets.size();
    if (packet_count < 3){ // minimum 3 packets
        return false;
    }

    // One Public-Key packet
    if (packets[0] -> get_tag() != key){
        return false;
    }
    
    // get key version
    std::string pub = packets[0] -> raw();
    uint8_t version = Tag6(pub).get_version();

    // Zero or more revocation signatures
    unsigned int i = 1;
    while (packets[i] -> get_tag() == 2){
        std::string tag2 = packets[i] -> raw();
        if (Tag2(tag2).get_type() == 0x20){ // Key revocation signature
            i++;
        }
        else{
            return false;
        }
    }

    // One or more User ID packets
    // Zero or more User Attribute packets
    //
    // User Attribute packets and User ID packets may be freely intermixed
    // in this section, so long as the signatures that follow them are
    // maintained on the proper User Attribute or User ID packet.

    while ((packets[i] -> get_tag() == 13) || (packets[i] -> get_tag() == 17)){
        // After each User ID packet, zero or more Signature packets (certifications)
        // After each User Attribute packet, zero or more Signature packets (certifications)
        i++;
        if (packets[i] -> get_tag() == 2){
            std::string tag2 = packets[i] -> raw();
            uint8_t sig_type = Tag2(tag2).get_type();
            if ((0x10 <= sig_type) && (sig_type <= 0x13)){ // (certifications)
                i++;
            }
        }
        else{
            return false;
        }
    }

    // Zero or more Subkey packets
    while ((packets[i] -> get_tag() == subkey)){
        if (version == 3){ // V3 keys MUST NOT have subkeys.
            return false;
        }
        // After each Subkey packet, one Signature packet, plus optionally a revocation
        i++;
        if (packets[i] -> get_tag() == 2){
            std::string tag2 = packets[i] -> raw();
            if (Tag2(tag2).get_type() == 18){ // Subkey binding signature
                i++;
                if (packets[i] -> get_tag() == 2){
                    tag2 = packets[i] -> raw();
                    if (Tag2(tag2).get_type() == 0x20){ // Key revocation signature
                        i++;
                    }
                    else{
                        break;
                    }
                }
                else{
                    return false;
                }
            }
            else{
                return false;
            }
        }
        else{
            return false;
        }
    }

    return true;
}

PGPKey::PGPKey():
   PGP()
{}

PGPKey::PGPKey(const PGPKey & copy):
    PGP(copy)
{}

PGPKey::PGPKey(std::string & data):
    PGP(data)
{}

PGPKey::PGPKey(std::ifstream & f):
    PGP(f)
{}

PGPKey::~PGPKey(){}

PGP::Ptr PGPKey::clone() const{
    return PGPKey::Ptr(new PGPKey(*this));
}

bool PGPKey::meaningful() const{
    return meaningful(ASCII_Armor);
}

PGPSecretKey::PGPSecretKey():
   PGPKey()
{}

PGPSecretKey::PGPSecretKey(const PGPSecretKey & copy):
    PGPKey(copy)
{}

PGPSecretKey::PGPSecretKey(std::string & data):
    PGPKey(data)
{}

PGPSecretKey::PGPSecretKey(std::ifstream & f):
    PGPKey(f)
{}

PGPSecretKey::~PGPSecretKey(){}

PGP::Ptr PGPSecretKey::clone() const{
    return PGPSecretKey::Ptr(new PGPSecretKey(*this));
}

bool PGPSecretKey::meaningful() const{
    return PGPKey::meaningful(2);
}

PGPPublicKey::PGPPublicKey():
   PGPKey()
{}

PGPPublicKey::PGPPublicKey(const PGPPublicKey & copy):
    PGPKey(copy)
{
    // armored = copy.armored;
    // ASCII_Armor = copy.ASCII_Armor;
    // Armor_Header = copy.Armor_Header;
    // packets = copy.get_packets_clone();
}

PGPPublicKey::PGPPublicKey(std::string & data):
    PGPKey(data)
{}

PGPPublicKey::PGPPublicKey(std::ifstream & f):
    PGPKey(f)
{}

PGPPublicKey::PGPPublicKey(const PGPSecretKey & sec):
    PGPKey()
{
    armored = sec.get_armored();
    ASCII_Armor = sec.get_ASCII_Armor();
    Armor_Header = sec.get_Armor_Header();
    
    // clone packets; convert secret packets into public ones
    for(const Packet::Ptr & p : sec.get_packets()){
        switch (p -> get_tag()){
            case 5:
            {
                std::string data = p -> raw();
                Packet::Ptr tag6(new Tag6(data));
                packets.push_back(tag6);
                break;
            }
            case 7:
            {
                std::string data = p -> raw();
                Packet::Ptr tag14(new Tag14(data));
                packets.push_back(tag14);
                break;
            }
            default:
                packets.push_back(p -> clone());
                break;
        }
    }
}

PGPPublicKey::~PGPPublicKey(){}

PGP::Ptr PGPPublicKey::clone() const{
    return PGPPublicKey::Ptr(new PGPPublicKey(*this));
}

bool PGPPublicKey::meaningful() const {
    return PGPKey::meaningful(1);
}

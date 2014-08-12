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

std::string PGPKey::keyid() const{
    for(Packet::Ptr const & p : packets){
        // find primary key
        if ((p -> get_tag() == 5) || (p -> get_tag() == 6)){
            std::string data = p -> raw();
            Tag6 tag6(data);
            return tag6.get_keyid();
        }
    }
    // if no primary key is found
    for(Packet::Ptr const & p : packets){
        // find subkey
        if ((p -> get_tag() == 7) || (p -> get_tag() == 14)){
            std::string data = p -> raw();
            Tag6 tag6(data);
            return tag6.get_keyid();
        }
    }
    throw std::runtime_error("Error: PGP block type is incorrect.");
    return ""; // should never reach here; mainly just to remove compiler warnings
}

// output is copied from gpg --list-keys
std::string PGPKey::list_keys() const{
    // scan for revoked keys
    std::map <std::string, std::string> revoked;
    for(Packet::Ptr const & p : packets){
        if (p -> get_tag() == 2){
            std::string raw = p -> raw();
            Tag2 tag2(raw);
            if ((tag2.get_type() == 0x20) || (tag2.get_type() == 0x28)){
                bool found = false;
                for(Tag2Subpacket::Ptr & s : tag2.get_unhashed_subpackets()){
                    if (s -> get_type() == 16){
                        raw = s -> raw();
                        Tag2Sub16 tag2sub16(raw);
                        revoked[tag2sub16.get_keyid()] = show_date(tag2.get_time());
                        found = true;
                    }
                }
                if (!found){
                    for(Tag2Subpacket::Ptr & s : tag2.get_hashed_subpackets()){
                        if (s -> get_type() == 16){
                            raw = s -> raw();
                            Tag2Sub16 tag2sub16(raw);
                            revoked[tag2sub16.get_keyid()] = show_date(tag2.get_time());
                            found = true;
                        }
                    }
                }
            }
        }
    }

    std::stringstream out;
    for(Packet::Ptr const & p : packets){
        std::string data = p -> raw();
        switch (p -> get_tag()){
            case 5: case 6: case 7: case 14:
                {
                    Tag6 tag6(data);
                    std::map <std::string, std::string>::iterator r = revoked.find(tag6.get_keyid());
                    std::stringstream s;
                    s << bitsize(tag6.get_mpi()[0]);
                    out << Public_Key_Type.at(p -> get_tag()) << "    " << zfill(s.str(), 4, ' ')
                           << Public_Key_Algorithm_Short.at(tag6.get_pka()) << "/"
                           << hexlify(tag6.get_keyid().substr(4, 4)) << " "
                           << show_date(tag6.get_time())
                           << ((r == revoked.end())?std::string(""):(std::string(" [revoked: ") + revoked[tag6.get_keyid()] + std::string("]")))
                           << "\n";
                }
                break;
            case 13:
                {
                    Tag13 tag13(data);
                    out << "uid                   " << tag13.raw() << "\n";
                }
                break;
            case 17:
                {
                    Tag17 tag17(data);
                    std::vector <Tag17Subpacket::Ptr> subpackets = tag17.get_attributes();
                    for(Tag17Subpacket::Ptr s : subpackets){
                        // since only subpacket type 1 is defined
                        data = s -> raw();
                        Tag17Sub1 sub1(data);
                        out << "att                   [jpeg image of size " << sub1.get_image().size() << "]\n";
                    }
                }
                break;
            case 2: default:
                break;
        }
    }
    return out.str();
}

bool PGPKey::meaningful() const{
    return meaningful(ASCII_Armor);
}

PGP::Ptr PGPKey::clone() const{
    return PGPKey::Ptr(new PGPKey(*this));
}

std::ostream & operator<<(std::ostream & stream, const PGPKey & pgp){
    stream << hexlify(pgp.keyid());
    return stream;
}

PGPSecretKey::PGPSecretKey():
   PGPKey()
{
    ASCII_Armor = 2;
}

PGPSecretKey::PGPSecretKey(const PGPSecretKey & copy):
    PGPKey(copy)
{
    if ((ASCII_Armor == 255) && meaningful()){
        ASCII_Armor = 2;
    }
}

PGPSecretKey::PGPSecretKey(std::string & data):
    PGPKey(data)
{
    if ((ASCII_Armor == 255) && meaningful()){
        ASCII_Armor = 2;
    }
}

PGPSecretKey::PGPSecretKey(std::ifstream & f):
    PGPKey(f)
{
    if ((ASCII_Armor == 255) && meaningful()){
        ASCII_Armor = 2;
    }
}

PGPSecretKey::~PGPSecretKey(){}

PGPPublicKey PGPSecretKey::pub() const {
    return Secret2PublicKey(*this);
}

bool PGPSecretKey::meaningful() const{
    return PGPKey::meaningful(2);
}

PGP::Ptr PGPSecretKey::clone() const{
    return PGPSecretKey::Ptr(new PGPSecretKey(*this));
}

std::ostream & operator<<(std::ostream & stream, const PGPSecretKey & pgp){
    stream << hexlify(pgp.keyid());
    return stream;
}

PGPPublicKey::PGPPublicKey():
   PGPKey()
{
    ASCII_Armor = 1;
}

PGPPublicKey::PGPPublicKey(const PGPPublicKey & copy):
    PGPKey(copy)
{
    if ((ASCII_Armor == 255) && meaningful()){
        ASCII_Armor = 1;
    }
}

PGPPublicKey::PGPPublicKey(std::string & data):
    PGPKey(data)
{
    if ((ASCII_Armor == 255) && meaningful()){
        ASCII_Armor = 1;
    }
}

PGPPublicKey::PGPPublicKey(std::ifstream & f):
    PGPKey(f)
{
    if ((ASCII_Armor == 255) && meaningful()){
        ASCII_Armor = 1;
    }
}

PGPPublicKey::PGPPublicKey(const PGPSecretKey & sec):
    PGPPublicKey(Secret2PublicKey(sec))
{}

PGPPublicKey::~PGPPublicKey(){}

bool PGPPublicKey::meaningful() const {
    return PGPKey::meaningful(1);
}

PGP::Ptr PGPPublicKey::clone() const{
    return PGPPublicKey::Ptr(new PGPPublicKey(*this));
}

std::ostream & operator<<(std::ostream & stream, const PGPPublicKey & pgp){
    stream << hexlify(pgp.keyid());
    return stream;
}

PGPPublicKey Secret2PublicKey(const PGPSecretKey & pri){
    PGPPublicKey pub;
    pub.set_armored(pri.get_armored());
    pub.set_ASCII_Armor(pri.get_ASCII_Armor());
    pub.set_Armor_Header(pri.get_Armor_Header());
    
    // clone packets; convert secret packets into public ones
    std::vector <Packet::Ptr> packets;
    for(Packet::Ptr const & p : pri.get_packets()){
        switch (p -> get_tag()){
            case 5:
            {
                std::string data = p -> raw();
                packets.push_back(Tag5(data).get_public_ptr());
                break;
            }
            case 7:
            {
                std::string data = p -> raw();
                packets.push_back(Tag7(data).get_public_ptr());
                break;
            }
            default:
                packets.push_back(p -> clone());
                break;
        }
    }
    pub.set_packets(packets);
    return pub;
}

#include "PGPKey.h"

bool PGPKey::meaningful(uint8_t type) const{
    uint8_t key, subkey;

    if (type == 1){ // Public Key
        key = 6;
        subkey = 14;
    }
    else if (type == 2){ // Private Key
        key = 5;
        subkey = 7;
    }
    else {
        throw std::runtime_error("Error: Non-PGP key in PGPKey structure.");
    }

    if (packets.size() < 3){ // minimum 3 packets: Primary Key + UID + Certification Signature
        return false;
    }

    // One Key packet
    if (packets[0] -> get_tag() != key){
        return false;
    }

    // get key version
    std::string pub = packets[0] -> raw();
    uint8_t version = Tag6(pub).get_version();

    // Zero or more revocation signatures
    unsigned int i = 1;
    while ((i < packets.size()) && (packets[i] -> get_tag() == 2)){
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
    bool uid = false;
    while ((i < packets.size()) && ((packets[i] -> get_tag() == 13) || (packets[i] -> get_tag() == 17))){
        // After each User ID packet, zero or more Signature packets (certifications)
        // After each User Attribute packet, zero or more Signature packets (certifications)
        if (packets[i] -> get_tag() == 13){
            uid = true;
        }

        i++;

        // make sure the next packet is a signature
        if ((i >= packets.size()) || (packets[i] -> get_tag() != 2)){
            return false;
        }

        // while the packets continue to be signature packets
        while ((i < packets.size()) && (packets[i] -> get_tag() == 2)){
            std::string tag2 = packets[i] -> raw();
            uint8_t sig_type = Tag2(tag2).get_type();
            if ((0x10 <= sig_type) && (sig_type <= 0x13)){ // make sure they are certifications
                i++;
            }
            else{
                return false;
            }
        }
    }

    if (!uid){ // at least one User ID packet
        return false;
    }

    // Zero or more Subkey packets
    while ((i < packets.size()) && (packets[i] -> get_tag() == subkey)){
        if (version == 3){ // V3 keys MUST NOT have subkeys.
            return false;
        }

        // After each Subkey packet, one Signature packet, plus optionally a revocation
        i++;

        // one Signature packet
        if ((i >= packets.size()) || (packets[i] -> get_tag() != 2)){
            return false;
        }

        // check that the Signature packet is a Subkey binding signature
        std::string tag2 = packets[i] -> raw();
        if (Tag2(tag2).get_type() != 0x18){ // type Subkey binding signature
            return false;
        }

        // optionally a revocation
        i++;
        if (i >= packets.size()){ // if there are no more packets to check
            return true;
        }

        // if the next packet is a subkey, go back to top of loop
        if (packets[i] -> get_tag() == subkey){
            continue;
        }
        else if (packets[i] -> get_tag() == 2){ // else if the next packet is a Signature packet
            tag2 = packets[i] -> raw();
            if (Tag2(tag2).get_type() == 0x20){ // check if it is a Key revocation signature
                i++;
            }
            else{ // if not
                return false;
            }
        }
        else{ // neither a subkey or a revocation signature
            return false;
        }
    }

    return true; // no subkeys
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

// output style is copied from gpg --list-keys
std::string PGPKey::list_keys() const{
    // scan for revoked keys
    std::map <std::string, std::string> revoked;
    for(Packet::Ptr const & p : packets){
        if (p -> get_tag() == 2){
            std::string data = p -> raw();
            Tag2 tag2(data);
            if ((tag2.get_type() == 0x20) || (tag2.get_type() == 0x28)){
                bool found = false;
                for(Tag2Subpacket::Ptr & s : tag2.get_unhashed_subpackets()){
                    if (s -> get_type() == 16){
                        data = s -> raw();
                        Tag2Sub16 tag2sub16(data);
                        revoked[tag2sub16.get_keyid()] = show_date(tag2.get_time());
                        found = true;
                    }
                }
                if (!found){
                    for(Tag2Subpacket::Ptr & s : tag2.get_hashed_subpackets()){
                        if (s -> get_type() == 16){
                            data = s -> raw();
                            Tag2Sub16 tag2sub16(data);
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
    return std::make_shared <PGPKey> (*this);
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
    return std::make_shared <PGPSecretKey> (*this);
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
    return std::make_shared <PGPPublicKey> (*this);
}

std::ostream & operator<<(std::ostream & stream, const PGPPublicKey & pgp){
    stream << hexlify(pgp.keyid());
    return stream;
}

PGPPublicKey Secret2PublicKey(const PGPSecretKey & pri){
    PGPPublicKey pub;
    pub.set_armored(pri.get_armored());
    pub.set_ASCII_Armor(1); // public key ASCII Armor Header value
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

    for(Packet::Ptr & p : packets){
        p.reset();
    }

    return pub;
}

Key::Ptr find_signing_key(const PGPKey::Ptr & key, const uint8_t tag, const std::string & keyid){
    if ((key -> get_ASCII_Armor() == 1) || (key -> get_ASCII_Armor() == 2)){
        std::vector <Packet::Ptr> packets = key -> get_packets();
        for(Packet::Ptr const & p : packets){
            if (p -> get_tag() == tag){
                Key::Ptr signer = nullptr;
                switch (tag){
                    case 5:
                        signer = std::make_shared <Tag5> ();
                        break;
                    case 6:
                        signer = std::make_shared <Tag6> ();
                        break;
                    case 7:
                        signer = std::make_shared <Tag7> ();
                        break;
                    case 14:
                        signer = std::make_shared <Tag14> ();
                        break;
                    default:
                        throw std::runtime_error("Error: Not a key tag.");
                        break;
                }

                std::string data = p -> raw();
                signer -> read(data);

                // make sure key has signing material
                if ((signer -> get_pka() == 1) || // RSA (Encrypt or Sign)
                    (signer -> get_pka() == 3) || // RSA Sign-Only
                    (signer -> get_pka() == 17)){ // DSA

                    // make sure the keyid matches the given one
                    // expects only full matches
                    if (keyid.size()){
                        if (signer -> get_keyid() == keyid){
                            return signer;
                        }
                        signer.reset();
                    }
                    else{
                        return signer;
                    }
                }
                signer.reset();
            }
        }
    }
    return nullptr;
}

Tag6::Ptr find_signing_key(const PGPPublicKey & key, const uint8_t tag, const std::string & keyid){
    Key::Ptr found = find_signing_key(std::make_shared <PGPKey> (key), tag);
    if (!found){
        return nullptr;
    }
    std::string data = found -> raw();
    return std::make_shared <Tag6> (data);
}

Tag5::Ptr find_signing_key(const PGPSecretKey & key, const uint8_t tag, const std::string & keyid){
    Key::Ptr found = find_signing_key(std::make_shared <PGPKey> (key), tag);
    if (!found){
        return nullptr;
    }
    std::string data = found -> raw();
    return std::make_shared <Tag5> (data);
}
#include "PGPKey.h"

bool PGPKey::meaningful(uint8_t type) const{
    uint8_t key, subkey;

    if (type == PGP::Type::PUBLIC_KEY_BLOCK){   
        key = 6;
        subkey = 14;
    }
    else if (type == PGP::Type::PRIVATE_KEY_BLOCK){
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

PGPKey::PGPKey()
    : PGP()
{}

PGPKey::PGPKey(const PGPKey & copy)
    : PGP(copy)
{}

PGPKey::PGPKey(const std::string & data)
    : PGP(data)
{}

PGPKey::PGPKey(std::istream & stream)
    : PGP(stream)
{}

PGPKey::~PGPKey(){}

std::string PGPKey::keyid() const{
    for(Packet::Ptr const & p : packets){
        // find primary key
        if ((p -> get_tag() == 5) || (p -> get_tag() == 6)){
            return Tag6(p -> raw()).get_keyid();
        }
    }
    // if no primary key is found
    for(Packet::Ptr const & p : packets){
        // find subkey
        if ((p -> get_tag() == 7) || (p -> get_tag() == 14)){
            return Tag6(p -> raw()).get_keyid();
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
            Tag2 tag2(p -> raw());
            if ((tag2.get_type() == 0x20) || (tag2.get_type() == 0x28)){
                bool found = false;
                for(Tag2Subpacket::Ptr & s : tag2.get_unhashed_subpackets()){
                    if (s -> get_type() == 16){
                        revoked[Tag2Sub16(s -> raw()).get_keyid()] = show_date(tag2.get_time());
                        found = true;
                    }
                }
                if (!found){
                    for(Tag2Subpacket::Ptr & s : tag2.get_hashed_subpackets()){
                        if (s -> get_type() == 16){
                            revoked[Tag2Sub16(s -> raw()).get_keyid()] = show_date(tag2.get_time());
                            found = true;
                        }
                    }
                }
            }
        }
    }

    std::stringstream out;
    for(Packet::Ptr const & p : packets){
        switch (p -> get_tag()){
            case 5: case 6: case 7: case 14:
                {
                    Tag6 tag6(p -> raw());
                    std::map <std::string, std::string>::iterator r = revoked.find(tag6.get_keyid());
                    std::stringstream s;
                    s << bitsize(tag6.get_mpi()[0]);
                    out << Public_Key_Type.at(p -> get_tag()) << "    " << zfill(s.str(), 4, ' ')
                        << PKA::Short.at(tag6.get_pka()) << "/"
                        << hexlify(tag6.get_keyid().substr(4, 4)) << " "
                        << show_date(tag6.get_time())
                        << ((r == revoked.end())?std::string(""):(std::string(" [revoked: ") + revoked[tag6.get_keyid()] + std::string("]")))
                        << "\n";
                }
                break;
            case 13:
                {
                    Tag13 tag13(p -> raw());
                    out << "uid                   " << tag13.raw() << "\n";
                }
                break;
            case 17:
                {
                    Tag17 tag17(p -> raw());
                    std::vector <Tag17Subpacket::Ptr> subpackets = tag17.get_attributes();
                    for(Tag17Subpacket::Ptr s : subpackets){
                        // since only subpacket type 1 is defined
                        out << "att                   [jpeg image of size " << Tag17Sub1(s -> raw()).get_image().size() << "]\n";
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
    return meaningful(type);
}

PGP::Ptr PGPKey::clone() const{
    return std::make_shared <PGPKey> (*this);
}

std::ostream & operator<<(std::ostream & stream, const PGPKey & pgp){
    stream << hexlify(pgp.keyid());
    return stream;
}

PGPSecretKey::PGPSecretKey()
    : PGPKey()
{
    type = PGP::Type::PRIVATE_KEY_BLOCK;
}

PGPSecretKey::PGPSecretKey(const PGPSecretKey & copy)
    : PGPKey(copy)
{
    if ((type == PGP::Type::UNKNOWN) && meaningful()){
        type = PGP::Type::PRIVATE_KEY_BLOCK;
    }
}

PGPSecretKey::PGPSecretKey(const std::string & data)
    : PGPKey(data)
{
    if ((type == PGP::Type::UNKNOWN) && meaningful()){
        type = PGP::Type::PRIVATE_KEY_BLOCK;
    }
}

PGPSecretKey::PGPSecretKey(std::istream & stream)
    : PGPKey(stream)
{
    if ((type == PGP::Type::UNKNOWN) && meaningful()){
        type = PGP::Type::PRIVATE_KEY_BLOCK;
    }
}

PGPSecretKey::~PGPSecretKey(){}

PGPPublicKey PGPSecretKey::get_public() const{
    PGPPublicKey pub;
    pub.set_armored(armored);
    pub.set_type(PGP::Type::PUBLIC_KEY_BLOCK);
    pub.set_keys(keys);

    // clone packets; convert secret packets into public ones
    PGP::Packets pub_packets;
    for(Packet::Ptr const & p : packets){
        switch (p -> get_tag()){
            case 5:
            {
                pub_packets.push_back(Tag5(p -> raw()).get_public_ptr());
                break;
            }
            case 7:
            {
                pub_packets.push_back(Tag7(p -> raw()).get_public_ptr());
                break;
            }
            default:
                pub_packets.push_back(p -> clone());
                break;
        }
    }

    pub.set_packets(pub_packets);

    return pub;
}

bool PGPSecretKey::meaningful() const{
    return PGPKey::meaningful(PGP::Type::PRIVATE_KEY_BLOCK);
}

PGP::Ptr PGPSecretKey::clone() const{
    return std::make_shared <PGPSecretKey> (*this);
}

std::ostream & operator<<(std::ostream & stream, const PGPSecretKey & pgp){
    stream << hexlify(pgp.keyid());
    return stream;
}

PGPPublicKey::PGPPublicKey()
    : PGPKey()
{
    type = PGP::Type::PUBLIC_KEY_BLOCK;
}

PGPPublicKey::PGPPublicKey(const PGPPublicKey & copy)
    : PGPKey(copy)
{
    if ((type == PGP::Type::UNKNOWN) && meaningful()){
        type = PGP::Type::PUBLIC_KEY_BLOCK;
    }
}

PGPPublicKey::PGPPublicKey(const std::string & data)
    : PGPKey(data)
{
    if ((type == PGP::Type::UNKNOWN) && meaningful()){
        type = PGP::Type::PUBLIC_KEY_BLOCK;
    }
}

PGPPublicKey::PGPPublicKey(std::istream & stream)
    : PGPKey(stream)
{
    if ((type == PGP::Type::UNKNOWN) && meaningful()){
        type = PGP::Type::PUBLIC_KEY_BLOCK;
    }
}

PGPPublicKey::PGPPublicKey(const PGPSecretKey & sec)
    : PGPPublicKey(sec.get_public())
{}

PGPPublicKey::~PGPPublicKey(){}

bool PGPPublicKey::meaningful() const{
    return PGPKey::meaningful(PGP::Type::PUBLIC_KEY_BLOCK);
}

PGPPublicKey & PGPPublicKey::operator=(const PGPPublicKey & pub){
    armored = pub.armored;
    type = pub.type;
    keys = pub.keys;
    packets = pub.packets;

    for(Packet::Ptr & p : packets){
        p = p -> clone();
    }

    return *this;
}

PGPPublicKey & PGPPublicKey::operator=(const PGPSecretKey & pri){
    return *this = pri.get_public();
}

PGP::Ptr PGPPublicKey::clone() const{
    return std::make_shared <PGPPublicKey> (*this);
}

std::ostream & operator<<(std::ostream & stream, const PGPPublicKey & pgp){
    stream << hexlify(pgp.keyid());
    return stream;
}

Key::Ptr find_signing_key(const PGPKey::Ptr & key, const uint8_t tag, const std::string & keyid){
    if ((key -> get_type() == PGP::Type::PUBLIC_KEY_BLOCK) ||
        (key -> get_type() == PGP::Type::PRIVATE_KEY_BLOCK)){
        std::vector <Packet::Ptr> packets = key -> get_packets();
        for(Packet::Ptr const & p : packets){
            if (p -> get_tag() == tag){
                Key::Ptr signer = nullptr;
                switch (tag){
                    case 5:
                        signer = std::make_shared <Tag5>  ();
                        break;
                    case 6:
                        signer = std::make_shared <Tag6>  ();
                        break;
                    case 7:
                        signer = std::make_shared <Tag7>  ();
                        break;
                    case 14:
                        signer = std::make_shared <Tag14> ();
                        break;
                    default:
                        throw std::runtime_error("Error: Not a key tag.");
                        break;
                }

                signer -> read(p -> raw());

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
                    }
                    else{
                        return signer;
                    }
                }
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
    return std::make_shared <Tag6> (found -> raw());
}

Tag5::Ptr find_signing_key(const PGPSecretKey & key, const uint8_t tag, const std::string & keyid){
    Key::Ptr found = find_signing_key(std::make_shared <PGPKey> (key), tag);
    if (!found){
        return nullptr;
    }
    return std::make_shared <Tag5> (found -> raw());
}
#include "PGPKey.h"

bool PGPKey::match(uint8_t type, std::string & error) const{
    // public or private key packets to look for
    uint8_t key, subkey;
    if (type == PGP::Type::PUBLIC_KEY_BLOCK){
           key = Packet::ID::Public_Key;
        subkey = Packet::ID::Public_Subkey;
    }
    else if (type == PGP::Type::PRIVATE_KEY_BLOCK){
           key = Packet::ID::Secret_Key;
        subkey = Packet::ID::Secret_Subkey;
    }
    else{
        error = "Error: Not a key type.";
        return false;
    }

    // minimum 2 packets: Primary Key + User ID
    if (packets.size() < 2){
        error = "Error: Not enough packets (minimum 2).";
        return false;
    }

    //   - One Public/Secret-Key packet
    if (packets[0] -> get_tag() != key){
        error = "Error: First packet is not a " + Packet::Name.at(key) + ".";
        return false;
    }

    // get version of primary key
    uint8_t primary_key_version = Tag6(packets[0] -> raw()).get_version();

    //   - Zero or more revocation signatures
    unsigned int i = 1;
    while ((i < packets.size()) && (packets[i] -> get_tag() == Packet::ID::Signature)){
        if (Tag2(packets[i] -> raw()).get_type() == Signature_Type::ID::Key_revocation_signature){
            i++;
        }
        else{
            error = "Error: Packet " + std::to_string(i) + " following " + Packet::Name.at(key) + " is not a key revocation signature.";
            return false;
        }
    }

    //   - One or more User ID packets
    //
    //   - After each User ID packet, zero or more Signature packets
    //     (certifications)
    //
    //   - Zero or more User Attribute packets
    //
    //   - After each User Attribute packet, zero or more Signature packets
    //     (certifications)
    //
    //   ...
    //
    // User Attribute packets and User ID packets may be freely intermixed
    // in this section, so long as the signatures that follow them are
    // maintained on the proper User Attribute or User ID packet.
    std::size_t user_id_count = 0;
    do{
        // make sure there is a User packet
        if ((packets[i] -> get_tag() != Packet::ID::User_ID) &&
            (packets[i] -> get_tag() != Packet::ID::User_Attribute)){
            error = "Error: Packet is not a User ID or User Attribute Packet.";
            return false;
        }

        // need at least one User ID packet
        user_id_count += (packets[i] -> get_tag() == Packet::ID::User_ID);

        // go to next packet
        i++;

        // Immediately following each User ID packet, there are zero or more
        // Signature packets. Each Signature packet is calculated on the
        // immediately preceding User ID packet and the initial Public-Key
        // packet. The signature serves to certify the corresponding public key
        // and User ID. In effect, the signer is testifying to his or her
        // belief that this public key belongs to the user identified by this
        // User ID.
        //
        // Within the same section as the User ID packets, there are zero or
        // more User Attribute packets. Like the User ID packets, a User
        // Attribute packet is followed by zero or more Signature packets
        // calculated on the immediately preceding User Attribute packet and the
        // initial Public-Key packet.
        if ((i >= packets.size()) ||
            (packets[i] -> get_tag() != Packet::ID::Signature)){
            break;
        }

        // make sure the signature type is a certification
        if (!Signature_Type::is_certification(Tag2(packets[i] -> raw()).get_type())){
            error = "Error: Signature type is not a certification packet.";
            return false;
        }

        // TODO: make sure signature matches the User packet
        if (packets[i - 1] -> get_tag() == Packet::ID::User_ID){

        }
        else if (packets[i - 1] -> get_tag() == Packet::ID::User_Attribute){

        }
        // else{}

        i++;
    } while ((i < packets.size())                                    &&
             ((packets[i] -> get_tag() == Packet::ID::User_ID)       ||
              (packets[i] -> get_tag() == Packet::ID::User_Attribute)));

    // need at least one User ID packet
    if (!user_id_count){
        error = "Error: Need at least one " + Packet::Name.at(Packet::ID::User_ID) + ".";
        return false;
    }

    //    - Zero or more Subkey packets
    while (((i + 1) < packets.size()) && (packets[i] -> get_tag() == subkey)){
        if (primary_key_version == 3){
            error = "Error: Version 3 keys MUST NOT have subkeys.";
            return false;
        }

        i++;

        //    - After each Subkey packet, one Signature packet, plus optionally a revocation
        if ((i >= packets.size())                             ||
            (packets[i] -> get_tag() != Packet::ID::Signature)){
            error = "Error: Signature packet not following subkey packet.";
            return false;
        }

        // check that the Signature packet is a Subkey binding signature
        if (Tag2(packets[i] -> raw()).get_type() != Signature_Type::ID::Subkey_Binding_Signature){
            error = "Error: Signature packet following subpacket is not of type " + Signature_Type::Name.at(Signature_Type::ID::Subkey_Binding_Signature) + ".";
            return false;
        }

        // TODO: make sure signature matches the signature packet

        i++;

        // if there are no more packets to check, stop checking
        if (i >= packets.size()){
            break;
        }

        // optionally a revocation
        if (packets[i] -> get_tag() == Packet::ID::Signature){
            if (Tag2(packets[i] -> raw()).get_type() == Signature_Type::ID::Key_revocation_signature){
                i++;
            }
            else{
                error = "Error: Signature packet following subkey signature is not a " + Signature_Type::Name.at(Signature_Type::ID::Key_revocation_signature) + ".";
                return false;
            }
        }
    }

    return (i == packets.size());
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
        if ((p -> get_tag() == Packet::ID::Secret_Key) ||
            (p -> get_tag() == Packet::ID::Public_Key)){
            return Tag6(p -> raw()).get_keyid();
        }
    }

    // if no primary key is found
    for(Packet::Ptr const & p : packets){
        // find subkey
        if ((p -> get_tag() == Packet::ID::Secret_Subkey) ||
            (p -> get_tag() == Packet::ID::Public_Subkey)){
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
        if (p -> get_tag() == Packet::ID::Signature){
            Tag2 tag2(p -> raw());
            if ((tag2.get_type() == Signature_Type::ID::Key_revocation_signature) ||
                (tag2.get_type() == Signature_Type::ID::Subkey_revocation_signature)){
                bool found = false;
                for(Tag2Subpacket::Ptr & s : tag2.get_unhashed_subpackets()){
                    if (s -> get_type() == Tag2Subpacket::ID::Issuer){
                        revoked[Tag2Sub16(s -> raw()).get_keyid()] = show_date(tag2.get_time());
                        found = true;
                    }
                }
                if (!found){
                    for(Tag2Subpacket::Ptr & s : tag2.get_hashed_subpackets()){
                        if (s -> get_type() == Tag2Subpacket::ID::Issuer){
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
        // if the packet is a key
        if ((p -> get_tag() == Packet::ID::Secret_Key)    ||
            (p -> get_tag() == Packet::ID::Public_Key)    ||
            (p -> get_tag() == Packet::ID::Secret_Subkey) ||
            (p -> get_tag() == Packet::ID::Public_Subkey)){
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
        // if the packet is a User ID
        else if (p -> get_tag() == Packet::ID::User_ID){
            Tag13 tag13(p -> raw());
            out << "uid                   " << tag13.raw() << "\n";
        }
        // if the packet is a User Attribute
        else if (p -> get_tag() == Packet::ID::User_Attribute){
            Tag17 tag17(p -> raw());
            std::vector <Tag17Subpacket::Ptr> subpackets = tag17.get_attributes();
            for(Tag17Subpacket::Ptr s : subpackets){
                // since only subpacket type 1 is defined
                out << "att                   [jpeg image of size " << Tag17Sub1(s -> raw()).get_image().size() << "]\n";
            }
        }
        // if the packet is a signature, do nothing
        // else if (p -> get_tag() == Packet::ID::Signature){}
        else{}
    }
    return out.str();
}

bool PGPKey::meaningful(std::string & error) const{
    return match(type, error);
}

bool PGPKey::meaningful() const{
    std::string error;
    return match(type, error);
}

PGP::Ptr PGPKey::clone() const{
    return std::make_shared <PGPKey> (*this);
}

std::ostream & operator<<(std::ostream & stream, const PGPKey & pgp){
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
    type = PGP::Type::PUBLIC_KEY_BLOCK;

    std::string error;
    if (!meaningful(error)){
        std::cerr << error << std::endl;
    }
}

PGPPublicKey::PGPPublicKey(const std::string & data)
    : PGPKey(data)
{
    type = PGP::Type::PUBLIC_KEY_BLOCK;

    std::string error;
    if (!meaningful(error)){
        std::cerr << error << std::endl;
    }
}

PGPPublicKey::PGPPublicKey(std::istream & stream)
    : PGPKey(stream)
{
    type = PGP::Type::PUBLIC_KEY_BLOCK;

    std::string error;
    if (!meaningful(error)){
        std::cerr << error << std::endl;
    }
}

PGPPublicKey::PGPPublicKey(const PGPSecretKey & sec)
    : PGPPublicKey(sec.get_public())
{}

PGPPublicKey::~PGPPublicKey(){}

bool PGPPublicKey::meaningful(std::string & error) const{
    return PGPKey::match(PGP::Type::PUBLIC_KEY_BLOCK, error);
}

bool PGPPublicKey::meaningful() const{
    std::string error;
    return PGPKey::match(PGP::Type::PUBLIC_KEY_BLOCK, error);
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

PGPSecretKey::PGPSecretKey()
    : PGPKey()
{
    type = PGP::Type::PRIVATE_KEY_BLOCK;
}

PGPSecretKey::PGPSecretKey(const PGPSecretKey & copy)
    : PGPKey(copy)
{
    type = PGP::Type::PRIVATE_KEY_BLOCK;

    std::string error;
    if (!meaningful(error)){
        std::cerr << error << std::endl;
    }
}

PGPSecretKey::PGPSecretKey(const std::string & data)
    : PGPKey(data)
{
    type = PGP::Type::PRIVATE_KEY_BLOCK;

    std::string error;
    if (!meaningful(error)){
        std::cerr << error << std::endl;
    }
}

PGPSecretKey::PGPSecretKey(std::istream & stream)
    : PGPKey(stream)
{
    type = PGP::Type::PRIVATE_KEY_BLOCK;

    std::string error;
    if (!meaningful(error)){
        std::cerr << error << std::endl;
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
        if (p -> get_tag() == Packet::ID::Secret_Key){
            pub_packets.push_back(Tag5(p -> raw()).get_public_ptr());
        }
        else if (p -> get_tag() == Packet::ID::Secret_Subkey){
            pub_packets.push_back(Tag7(p -> raw()).get_public_ptr());
        }
        else{
            pub_packets.push_back(p -> clone());
        }
    }

    pub.set_packets(pub_packets);

    return pub;
}

bool PGPSecretKey::meaningful(std::string & error) const{
    return PGPKey::match(PGP::Type::PRIVATE_KEY_BLOCK, error);
}

bool PGPSecretKey::meaningful() const{
    std::string error;
    return PGPKey::match(PGP::Type::PRIVATE_KEY_BLOCK, error);
}

PGP::Ptr PGPSecretKey::clone() const{
    return std::make_shared <PGPSecretKey> (*this);
}

std::ostream & operator<<(std::ostream & stream, const PGPSecretKey & pgp){
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
                if (tag == Packet::ID::Secret_Key){
                    signer = std::make_shared <Tag5>  ();
                }
                else if (tag == Packet::ID::Public_Key){
                    signer = std::make_shared <Tag6>  ();
                }
                else if (tag == Packet::ID::Secret_Subkey){
                    signer = std::make_shared <Tag7>  ();
                }
                else if (tag == Packet::ID::Public_Subkey){
                    signer = std::make_shared <Tag14> ();
                }
                else{
                    throw std::runtime_error("Error: Not a key tag.");
                }

                signer -> read(p -> raw());

                // make sure key has signing material
                if ((signer -> get_pka() == PKA::ID::RSA_Encrypt_or_Sign) ||
                    (signer -> get_pka() == PKA::ID::RSA_Sign_Only)       ||
                    (signer -> get_pka() == PKA::ID::DSA)){

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
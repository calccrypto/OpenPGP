#include "PGPKey.h"

PGPKey::PGPKey()
    : PGP()
{}

PGPKey::PGPKey(const PGP & copy)
    : PGP(copy)
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
    return (((type == PGP::Type::PUBLIC_KEY_BLOCK)  && PGP::meaningful_PUBLIC_KEY_BLOCK(error)) ||
            ((type == PGP::Type::PRIVATE_KEY_BLOCK) && PGP::meaningful_PRIVATE_KEY_BLOCK(error)));
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
{}

PGPPublicKey::PGPPublicKey(const PGPKey & copy)
    : PGPKey(copy)
{}

PGPPublicKey::PGPPublicKey(const std::string & data)
    : PGPKey(data)
{}

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
    return ((type == PGP::Type::PUBLIC_KEY_BLOCK) && meaningful_PUBLIC_KEY_BLOCK(error));
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

PGPSecretKey::PGPSecretKey(const PGPKey & copy)
    : PGPKey(copy)
{}

PGPSecretKey::PGPSecretKey(const PGPSecretKey & copy)
    : PGPKey(copy)
{}

PGPSecretKey::PGPSecretKey(const std::string & data)
    : PGPKey(data)
{}

PGPSecretKey::PGPSecretKey(std::istream & stream)
    : PGPKey(stream)
{}

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
    return ((type == PGP::Type::PRIVATE_KEY_BLOCK) && meaningful_PRIVATE_KEY_BLOCK(error));
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
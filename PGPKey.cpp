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
{
    // warn if packet sequence is not meaningful
    std::string error;
    if (!meaningful(error)){
        std::cerr << error << std::endl;
    }
}

PGPKey::PGPKey(std::istream & stream)
    : PGP(stream)
{
    // warn if packet sequence is not meaningful
    std::string error;
    if (!meaningful(error)){
        std::cerr << error << std::endl;
    }
}

PGPKey::~PGPKey(){}

std::string PGPKey::keyid() const{
    if (!meaningful()){
        throw std::runtime_error("Error: Bad Key.");
    }

    // guaranteed to have at least 2 packets
    return std::static_pointer_cast <Key> (packets[0]) -> get_keyid();
}

// output style is copied from gpg --list-keys
std::string PGPKey::list_keys() const{
    // primary key id
    const std::string id = keyid();

    // scan for revocation and expiration time
    std::string revoked = "";
    std::string expire = "";
    for(Packet::Ptr const & p : packets){
        if (p -> get_tag() == Packet::SIGNATURE){
            Tag2::Ptr tag2 = std::static_pointer_cast <Tag2> (p);

            // only check signature packets that were issued by the primary key
            if (tag2 -> get_keyid() == id){
                if ((tag2 -> get_type() == Signature_Type::KEY_REVOCATION_SIGNATURE) ||
                    (tag2 -> get_type() == Signature_Type::SUBKEY_REVOCATION_SIGNATURE)){
                    // keep only last value found
                    revoked = show_date(tag2 -> get_time());
                }

                // allow for values to be overwritten: use last expiration packet
                time_t create_time = 0;
                time_t expire_dt = 0;

                // search hashed subpackets
                for(Tag2Subpacket::Ptr const s : tag2 -> get_hashed_subpackets()){
                    if (s -> get_type() == Tag2Subpacket::SIGNATURE_CREATION_TIME){
                        create_time = std::static_pointer_cast <Tag2Sub2> (s) -> get_time();
                    }
                    else if (s -> get_type() == Tag2Subpacket::KEY_EXPIRATION_TIME){
                        expire_dt = std::static_pointer_cast <Tag2Sub9> (s) -> get_dt();
                    }
                }

                // search unhashed subpackets
                for(Tag2Subpacket::Ptr const s : tag2 -> get_unhashed_subpackets()){
                    if (s -> get_type() == Tag2Subpacket::SIGNATURE_CREATION_TIME){
                        create_time = std::static_pointer_cast <Tag2Sub2> (s) -> get_time();
                    }
                    else if (s -> get_type() == Tag2Subpacket::KEY_EXPIRATION_TIME){
                        expire_dt = std::static_pointer_cast <Tag2Sub9> (s) -> get_dt();
                    }
                }

                // only add entry if expiration time is present
                if (expire_dt){
                    if (!create_time){
                        expire = show_dt(expire_dt);
                    }
                    else{
                        expire = show_date(create_time + expire_dt);
                    }
                }
            }
        }
    }

    // print Key and User packets
    std::stringstream out;
    for(Packet::Ptr const & p : packets){
        // if the packet is a key
        if (Packet::is_key_packet(p -> get_tag())){
            Key::Ptr key = std::static_pointer_cast <Key> (p);
            out << Public_Key_Type.at(p -> get_tag()) << "   " << std::setfill(' ') << std::setw(4) << std::to_string(bitsize(key -> get_mpi()[0]))
                << PKA::SHORT.at(key -> get_pka()) << "/"
                << hexlify(key -> get_keyid().substr(4, 4)) << " "
                << show_date(key -> get_time());

            // revocation has priority
            if (revoked.size()){
                out << " [revoked: " << revoked << "]";
            }
            else if (expire.size()){
                out << " [expires: " << expire << "]";
            }

            out << "\n";
        }
        // if the packet is a User ID
        else if (p -> get_tag() == Packet::USER_ID){
            out << "uid                   " << std::static_pointer_cast <Tag13> (p) -> get_contents() << "\n";
        }
        // if the packet is a User Attribute
        else if (p -> get_tag() == Packet::USER_ATTRIBUTE){
            for(Tag17Subpacket::Ptr const & s : std::static_pointer_cast <Tag17> (p) -> get_attributes()){
                // since only subpacket type 1 is defined
                out << "att                   [jpeg image of size " << std::static_pointer_cast <Tag17Sub1> (s) -> get_image().size() << "]\n";
            }
        }
        // if the packet is a signature, do nothing
        // else if (p -> get_tag() == Packet::SIGNATURE){}
        else{}
    }

    return out.str();
}

bool PGPKey::meaningful(const PGP & pgp, std::string & error){
    // public or private key packets to look for
    uint8_t key, subkey;
    if (pgp.get_type() == PUBLIC_KEY_BLOCK){
           key = Packet::PUBLIC_KEY;
        subkey = Packet::PUBLIC_SUBKEY;
    }
    else if (pgp.get_type() == PRIVATE_KEY_BLOCK){
           key = Packet::SECRET_KEY;
        subkey = Packet::SECRET_SUBKEY;
    }
    else{
        error += "Error: Bad key type: " + std::to_string(pgp.get_type()) + "\n";
        return false;
    }

    const Packets & packets = pgp.get_packets();

    // minimum 2 packets: Primary Key + User ID
    if (packets.size() < 2){
        error += "Error: Not enough packets (minimum 2).\n";
        return false;
    }

    //   - One Public/Secret-Key packet
    if (packets[0] -> get_tag() != key){
        error += "Error: First packet is not a " + Packet::NAME.at(key) + ".\n";
        return false;
    }

    // get version of primary key
    uint8_t primary_key_version = std::static_pointer_cast <Key> (packets[0]) -> get_version();

    //   - Zero or more revocation signatures
    unsigned int i = 1;
    while ((i < packets.size()) && (packets[i] -> get_tag() == Packet::SIGNATURE)){
        if (std::static_pointer_cast <Tag2> (packets[i]) -> get_type() == Signature_Type::KEY_REVOCATION_SIGNATURE){
            std::cerr << "Warning: Revocation Signature found on primary key." << std::endl;
            i++;
        }
        else{
            error += "Error: Packet " + std::to_string(i) + " following " + Packet::NAME.at(key) + " is not a key revocation signature.\n";
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
        if ((packets[i] -> get_tag() != Packet::USER_ID)       &&
            (packets[i] -> get_tag() != Packet::USER_ATTRIBUTE)){
            error += "Error: Packet is not a User ID or User Attribute Packet.\n";
            return false;
        }

        // need at least one User ID packet
        user_id_count += (packets[i] -> get_tag() == Packet::USER_ID);

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
        while ((i < packets.size()) && (packets[i] -> get_tag() == Packet::SIGNATURE)){
            #ifndef GPG_COMPATIBLE
            // make sure the signature type is a certification
            if (!Signature_Type::is_certification(std::static_pointer_cast <Tag2> (packets[i]) -> get_type())){
                error += "Error: Signature type is not a certification packet.\n";
                return false;
            }
            #endif

            i++;
        }
    } while ((i < packets.size()) &&
             (Packet::is_user(packets[i] -> get_tag())));

    // need at least one User ID packet
    if (!user_id_count){
        error += "Error: Need at least one " + Packet::NAME.at(Packet::USER_ID) + ".\n";
        return false;
    }

    //    - Zero or more Subkey packets
    while ((i + 1) < packets.size()){
        if  (packets[i] -> get_tag() != subkey){
            error += "Error: Bad subkey packet.\n";
            return false;
        }

        if (primary_key_version == 3){
            error += "Error: Version 3 keys MUST NOT have subkeys.\n";
            return false;
        }

        i++;

        //    - After each Subkey packet, one Signature packet, plus optionally a revocation
        if ((i >= packets.size())                         ||
            (packets[i] -> get_tag() != Packet::SIGNATURE)){
            error += "Error: Signature packet not following subkey packet.\n";
            return false;
        }

        // #ifndef GPG_COMPATIBLE
        // // check that the Signature packet is a Subkey binding signature
        // if (std::static_pointer_cast <Tag2> (packets[i]) -> get_type() != Signature_Type::SUBKEY_BINDING_SIGNATURE){
            // error += "Error: Signature packet following subpacket is not of type " + Signature_Type::NAME.at(Signature_Type::SUBKEY_BINDING_SIGNATURE) + ".\n";
            // return false;
        // }
        // #endif

        i++;

        // if there are no more packets to check, stop checking
        if (i >= packets.size()){
            break;
        }

        // optionally a revocation
        if (packets[i] -> get_tag() == Packet::SIGNATURE){
            if (std::static_pointer_cast <Tag2> (packets[i]) -> get_type() == Signature_Type::SUBKEY_REVOCATION_SIGNATURE){
                std::cerr << "Warning: Revocation Signature found on subkey." << std::endl;
                i++;
            }
            #ifndef GPG_COMPATIBLE
            else{
                error += "Error: Signature packet following subkey signature is not a " + Signature_Type::NAME.at(Signature_Type::SUBKEY_REVOCATION_SIGNATURE) + ".\n";
                return false;
            }
            #endif
        }
    }

    // the index should be at the end of the packets
    return (i == packets.size());
}

bool PGPKey::meaningful(const PGP & pgp){
    std::string error;
    return meaningful(pgp, error);
}

bool PGPKey::meaningful(std::string & error) const{
    return meaningful(*this, error);
}

bool PGPKey::meaningful() const{
    std::string error;
    return meaningful(error);
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
    type = PUBLIC_KEY_BLOCK;
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
{}

PGPPublicKey::PGPPublicKey(const PGPSecretKey & sec)
    : PGPPublicKey(sec.get_public())
{}

PGPPublicKey::~PGPPublicKey(){}

bool PGPPublicKey::meaningful(std::string & error) const{
    if (type != PUBLIC_KEY_BLOCK){
        error += "Error: ASCII Armor type is not PUBLIC_KEY_BLOCK.\n";
        return false;
    }

    return PGPKey::meaningful(*this, error);
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
    type = PRIVATE_KEY_BLOCK;
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
    pub.set_type(PUBLIC_KEY_BLOCK);
    pub.set_keys(keys);

    // clone packets; convert secret packets into public ones
    Packets pub_packets;
    for(Packet::Ptr const & p : packets){
        if (p -> get_tag() == Packet::SECRET_KEY){
            pub_packets.push_back(std::static_pointer_cast <Tag5> (p) -> get_public_ptr());
        }
        else if (p -> get_tag() == Packet::SECRET_SUBKEY){
            pub_packets.push_back(std::static_pointer_cast <Tag7> (p) -> get_public_ptr());
        }
        else{
            pub_packets.push_back(p -> clone());
        }
    }

    pub.set_packets(pub_packets);

    return pub;
}

bool PGPSecretKey::meaningful(std::string & error) const{
    if (type != PRIVATE_KEY_BLOCK){
        error += "Error: ASCII Armor type is not PRIVATE_KEY_BLOCK.\n";
        return false;
    }

    return PGPKey::meaningful(*this, error);
}

PGP::Ptr PGPSecretKey::clone() const{
    return std::make_shared <PGPSecretKey> (*this);
}

std::ostream & operator<<(std::ostream & stream, const PGPSecretKey & pgp){
    stream << hexlify(pgp.keyid());
    return stream;
}

Key::Ptr find_signing_key(const PGPKey & key){
    // if the key is not actually a key
    std::string error;
    if (!key.meaningful(error)){
        return nullptr;
    }

    for(Packet::Ptr const & p : key.get_packets()){
        if (Packet::is_key_packet(p -> get_tag())){ // primary key or subkey
            Key::Ptr signing = std::static_pointer_cast <Key> (p);

            // make sure key has signing material
            if (PKA::can_sign(signing -> get_pka())){
                return signing;
            }
        }
    }

    return nullptr;
}

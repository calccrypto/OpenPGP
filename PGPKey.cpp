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
    std::string error;
    if (!meaningful(error)){
        throw std::runtime_error("Error: Bad Key.");
    }

    return std::static_pointer_cast <Key> (packets[0]) -> get_keyid();
}

std::string PGPKey::fingerprint() const{
    std::string error;
    if (!meaningful(error)){
        throw std::runtime_error("Error: Bad Key.");
    }

    return std::static_pointer_cast <Key> (packets[0]) -> get_fingerprint();
}


// output style inspired by gpg and SKS Keyserver/pgp.mit.edu
std::string PGPKey::list_keys(const std::size_t indents, const std::size_t indent_size) const{
    std::string error;
    if (!meaningful(error)){
        error += "Error: Key data not meaningful.\n";
        return "";
    }

    const std::string indent(indents * indent_size, ' ');

    // print Key and User packets
    std::stringstream out;
    for(Packet::Ptr const & p : packets){
        // primary key/subkey
        if (Packet::is_key_packet(p -> get_tag())){
            const Key::Ptr key = std::static_pointer_cast <Key> (p);

            if (Packet::is_subkey(p -> get_tag())){
                out << "\n";
            }

            out << indent << Public_Key_Type.at(p -> get_tag()) << "  " << std::setfill(' ') << std::setw(4) << std::to_string(bitsize(key -> get_mpi()[0]))
                << indent << PKA::SHORT.at(key -> get_pka()) << "/"
                << indent << hexlify(key -> get_keyid().substr(4, 4)) << " "
                << indent << show_date(key -> get_time());
        }
        // User ID
        else if (p -> get_tag() == Packet::USER_ID){
            out << "\n"
                << indent << "uid " << std::static_pointer_cast <Tag13> (p) -> get_contents();
        }
        // User Attribute
        else if (p -> get_tag() == Packet::USER_ATTRIBUTE){
            for(Tag17Subpacket::Ptr const & s : std::static_pointer_cast <Tag17> (p) -> get_attributes()){
                // since only subpacket type 1 is defined
                out << "\n"
                    << indent << "att  att  [jpeg image of size " << std::static_pointer_cast <Tag17Sub1> (s) -> get_image().size() << "]";
            }
        }
        // Signature
        else if (p -> get_tag() == Packet::SIGNATURE){
            out << indent << "sig ";

            const Tag2::Ptr sig = std::static_pointer_cast <Tag2> (p);
            if (Signature_Type::is_revocation(sig -> get_type())){
                out << "revok";
            }
            else if (sig -> get_type() == Signature_Type::SUBKEY_BINDING_SIGNATURE){
                out << "sbind";
            }
            else{
                out << " sig ";
            }

            const std::array <uint32_t, 3> times = sig -> get_times();  // {signature creation time, signature expiration time, key expiration time}
            out << "  " << hexlify(sig -> get_keyid().substr(4, 4));

            // signature creation time (should always exist)
            if (times[0]){
                out << " " << show_date(times[0]);
            }
            // else{
                // out << " " << std::setfill(' ') << std::setw(10);
            // }

            // if the signature expires
            if (times[1]){
                out << " " << show_date(times[1]);
            }
            else{
                out << " " << std::setfill(' ') << std::setw(10);
            }

            // if the key expires
            if (times[2]){
                out << " " << show_date(times[2]);
            }
            else{
                out << " " << std::setfill(' ') << std::setw(10);
            }
        }
        else{}

        out << "\n";
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
    const uint8_t primary_key_version = std::static_pointer_cast <Key> (packets[0]) -> get_version();

    //   - Zero or more revocation signatures
    unsigned int i = 1;
    while ((i < packets.size()) && (packets[i] -> get_tag() == Packet::SIGNATURE)){
        if (std::static_pointer_cast <Tag2> (packets[i]) -> get_type() == Signature_Type::KEY_REVOCATION_SIGNATURE){
            error += "Warning: Revocation Signature found on primary key.\n";
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
    Tag13::Ptr user_id = nullptr;
    do{
        // make sure there is a User packet
        if ((packets[i] -> get_tag() != Packet::USER_ID)       &&
            (packets[i] -> get_tag() != Packet::USER_ATTRIBUTE)){
            error += "Error: Packet is not a User ID or User Attribute Packet.\n";
            return false;
        }

        const User::Ptr user = std::static_pointer_cast <User> (packets[i]);
        if (user -> get_tag() == Packet::USER_ID){
            user_id = std::static_pointer_cast <Tag13> (user);
        }

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
            const Tag2::Ptr sig = std::static_pointer_cast <Tag2> (packets[i]);
            if (!Signature_Type::is_certification(sig -> get_type())){
                // User IDs can have revocation signatures
                if ((user -> get_tag() == Packet::USER_ID) &&
                    (sig -> get_type() == Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE)){
                    error += "Warning: Revocation Signature found on UID.\n";
                }
                else{
                    error += "Error: Signature is not a certification or revocation.\n";
                    return false;
                }
            }

            i++;
        }
    } while ((i < packets.size()) &&
             (Packet::is_user(packets[i] -> get_tag())));

    // need at least one User ID packet
    if (!user_id){
        error += "Error: Need at least one " + Packet::NAME.at(Packet::USER_ID) + ".\n";
        return false;
    }

    //    - Zero or more Subkey packets
    while (i < packets.size()){
        if  (packets[i] -> get_tag() != subkey){
            error += "Error: Bad subkey packet.\n";
            return false;
        }

        if (primary_key_version == 3){
            error += "Error: Version 3 keys MUST NOT have subkeys.\n";
            return false;
        }

        i++;

        // Each Subkey packet MUST be followed by one Signature packet, which
        // should be a subkey binding signature issued by the top-level key.
        // For subkeys that can issue signatures, the subkey binding signature
        // MUST contain an Embedded Signature subpacket with a primary key
        // binding signature (0x19) issued by the subkey on the top-level key.
        //
        // Subkey and Key packets may each be followed by a revocation Signature
        // packet to indicate that the key is revoked. Revocation signatures
        // are only accepted if they are issued by the key itself, or by a key
        // that is authorized to issue revocations via a Revocation Key
        // subpacket in a self-signature by the top-level key.

        //    - After each Subkey packet, one Signature packet, plus optionally a revocation
        bool subkey_binding = false;
        while ((i < packets.size()) &&
               (packets[i] -> get_tag() == Packet::SIGNATURE)){
            const Tag2::Ptr sig = std::static_pointer_cast <Tag2> (packets[i]);
            if (sig -> get_type() == Signature_Type::SUBKEY_REVOCATION_SIGNATURE){
                error += "Warning: Revocation Signature found on subkey.\n";
            }
            // at least one of the signatures should be a subkey binding signature (?)
            else if (sig -> get_type() == Signature_Type::SUBKEY_BINDING_SIGNATURE){
                subkey_binding = true;
            }

            i++;
        }

        if (!subkey_binding){
            error += "Error: No " + Signature_Type::NAME.at(Signature_Type::SUBKEY_BINDING_SIGNATURE) + " packet found following subkey.\n";
            return false;
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
{}

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

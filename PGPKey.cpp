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
    for(Packet::Ptr const & p : packets){
        // find primary key
        if ((p -> get_tag() == Packet::SECRET_KEY) ||
            (p -> get_tag() == Packet::PUBLIC_KEY)){
            return std::static_pointer_cast <Tag6> (p) -> get_keyid();
        }
    }

    // if no primary key is found
    for(Packet::Ptr const & p : packets){
        // find subkey
        if ((p -> get_tag() == Packet::SECRET_SUBKEY) ||
            (p -> get_tag() == Packet::PUBLIC_SUBKEY)){
            return std::static_pointer_cast <Tag6> (p) -> get_keyid();
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
        if (p -> get_tag() == Packet::SIGNATURE){
            Tag2::Ptr tag2 = std::static_pointer_cast <Tag2> (p);
            if ((tag2 -> get_type() == Signature_Type::KEY_REVOCATION_SIGNATURE) ||
                (tag2 -> get_type() == Signature_Type::SUBKEY_REVOCATION_SIGNATURE)){
                revoked[tag2 -> get_keyid()] = show_date(tag2 -> get_time());
            }
        }
    }

    std::stringstream out;
    for(Packet::Ptr const & p : packets){
        // if the packet is a key
        if (Packet::is_key_packet(p -> get_tag())){
            Key::Ptr key = std::static_pointer_cast <Tag6> (p);
            std::map <std::string, std::string>::iterator r = revoked.find(key -> get_keyid());
            std::stringstream s;
            s << bitsize(key -> get_mpi()[0]);
            out << Public_Key_Type.at(p -> get_tag()) << "    " << zfill(s.str(), 4, ' ')
                << PKA::SHORT.at(key -> get_pka()) << "/"
                << hexlify(key -> get_keyid().substr(4, 4)) << " "
                << show_date(key -> get_time())
                << ((r == revoked.end())?std::string(""):(std::string(" [revoked: ") + revoked[key -> get_keyid()] + std::string("]")))
                << "\n";
        }
        // if the packet is a User ID
        else if (p -> get_tag() == Packet::USER_ID){
            out << "uid                   " << std::static_pointer_cast <Tag13> (p) -> get_contents() << "\n";
        }
        // if the packet is a User Attribute
        else if (p -> get_tag() == Packet::USER_ATTRIBUTE){
            for(Tag17Subpacket::Ptr s : std::static_pointer_cast <Tag17> (p) -> get_attributes()){
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
        error += "Error: Bad key type.\n";
        return false;
    }

    const Packets & pkts = pgp.get_packets();

    // revocation certificates are placed in PUBLIC KEY BLOCKs
    // and have only one signature packet???
    if ((pkts.size() == 1)                         &&
        (pkts[0] -> get_tag() == Packet::SIGNATURE)){
        return (std::static_pointer_cast <Tag2> (pkts[0]) -> get_type() == Signature_Type::KEY_REVOCATION_SIGNATURE);
    }

    // minimum 2 packets: Primary Key + User ID
    else if (pkts.size() < 2){
        error += "Error: Not enough packets (minimum 2).\n";
        return false;
    }

    //   - One Public/Secret-Key packet
    if (pkts[0] -> get_tag() != key){
        error += "Error: First packet is not a " + Packet::NAME.at(key) + ".\n";
        return false;
    }

    // get version of primary key
    uint8_t primary_key_version = std::static_pointer_cast <Key> (pkts[0]) -> get_version();

    //   - Zero or more revocation signatures
    unsigned int i = 1;
    while ((i < pkts.size()) && (pkts[i] -> get_tag() == Packet::SIGNATURE)){
        if (std::static_pointer_cast <Tag2> (pkts[i]) -> get_type() == Signature_Type::KEY_REVOCATION_SIGNATURE){
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
        if ((pkts[i] -> get_tag() != Packet::USER_ID)       &&
            (pkts[i] -> get_tag() != Packet::USER_ATTRIBUTE)){
            error += "Error: Packet is not a User ID or User Attribute Packet.\n";
            return false;
        }

        // need at least one User ID packet
        user_id_count += (pkts[i] -> get_tag() == Packet::USER_ID);

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
        while ((i < pkts.size()) && (pkts[i] -> get_tag() == Packet::SIGNATURE)){
            // make sure the signature type is a certification
            if (!Signature_Type::is_certification(std::static_pointer_cast <Tag2> (pkts[i]) -> get_type())){
                error += "Error: Signature type is not a certification packet.\n";
                return false;
            }

            // TODO make sure signature matches the User packet
            if (pkts[i - 1] -> get_tag() == Packet::USER_ID){

            }
            else if (pkts[i - 1] -> get_tag() == Packet::USER_ATTRIBUTE){

            }
            // else{}

            i++;
        }
    } while ((i < pkts.size()) &&
             (Packet::is_user(pkts[i] -> get_tag())));

    // need at least one User ID packet
    if (!user_id_count){
        error += "Error: Need at least one " + Packet::NAME.at(Packet::USER_ID) + ".\n";
        return false;
    }

    //    - Zero or more Subkey packets
    while (((i + 1) < pkts.size()) && (pkts[i] -> get_tag() == subkey)){
        if (primary_key_version == 3){
            error += "Error: Version 3 keys MUST NOT have subkeys.\n";
            return false;
        }

        i++;

        //    - After each Subkey packet, one Signature packet, plus optionally a revocation
        if ((i >= pkts.size())                             ||
            (pkts[i] -> get_tag() != Packet::SIGNATURE)){
            error += "Error: Signature packet not following subkey packet.\n";
            return false;
        }

        // check that the Signature packet is a Subkey binding signature
        if (std::static_pointer_cast <Tag2> (pkts[i]) -> get_type() != Signature_Type::SUBKEY_BINDING_SIGNATURE){
            error += "Error: Signature packet following subpacket is not of type " + Signature_Type::NAME.at(Signature_Type::SUBKEY_BINDING_SIGNATURE) + ".\n";
            return false;
        }

        // TODO: make sure signature matches the signature packet

        i++;

        // if there are no more packets to check, stop checking
        if (i >= pkts.size()){
            break;
        }

        // optionally a revocation
        if (pkts[i] -> get_tag() == Packet::SIGNATURE){
            if (std::static_pointer_cast <Tag2> (pkts[i]) -> get_type() == Signature_Type::KEY_REVOCATION_SIGNATURE){
                std::cerr << "Warning: Revocation Signature found on subkey." << std::endl;
                i++;
            }
            else{
                error += "Error: Signature packet following subkey signature is not a " + Signature_Type::NAME.at(Signature_Type::KEY_REVOCATION_SIGNATURE) + ".\n";
                return false;
            }
        }
    }

    // the index should be at the end of the packets
    return (i == pkts.size());
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
        error += "Error: Key is not a PUBLIC KEY BLOCK.\n";
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
    pub.set_type(PRIVATE_KEY_BLOCK);
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
        error += "Error: Key is not a PRIVATE KEY BLOCK.\n";
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

Tag5::Ptr find_signing_key(const PGPSecretKey & pri, const std::string & ID){
    // if the key is not actually a secret key
    std::string error;
    if (!pri.meaningful(error)){
        return nullptr;
    }

    Tag5::Ptr key = nullptr;
    for(Packet::Ptr const & p : pri.get_packets()){
        if (Packet::is_secret(p -> get_tag())){                             // primary key or subkey
            key = std::static_pointer_cast <Tag5> (p);

            if (!ID.size()                ||                                // no ID given
                (key -> get_keyid() == ID)){                                // or if the ID matches

                // make sure key has signing material
                if (PKA::can_sign(key -> get_pka())){
                    return key;
                }
            }
        }
        else if (p -> get_tag() == Packet::USER_ID){                        // User ID packet
            Tag13::Ptr user = std::static_pointer_cast <Tag13> (p);

            if (ID.size() &&                                                // ID was given
                (user -> get_contents().find(ID) != std::string::npos)){    // ID is contained in User ID contents
                // make sure key has signing material
                if (PKA::can_sign(key -> get_pka())){
                    return key;
                }
            }
        }
        // else if (p -> get_tag() == Packet::USER_ATTRIBUTE){}
    }

    return nullptr;
}

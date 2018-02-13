#include "Key.h"

namespace OpenPGP {

Key::Key()
    : PGP()
{}

Key::Key(const PGP & copy)
    : PGP(copy)
{}

Key::Key(const Key & copy)
    : PGP(copy)
{}

Key::Key(const std::string & data)
    : PGP(data)
{
    // warn if packet sequence is not meaningful
    if (!meaningful()){
        throw std::runtime_error("Error: Data does not form a meaningful PGP Key");
    }
}

Key::Key(std::istream & stream)
    : PGP(stream)
{
    // warn if packet sequence is not meaningful
    if (!meaningful()){
        throw std::runtime_error("Error: Data does not form a meaningful PGP Key");
    }
}

Key::~Key(){}

std::string Key::keyid() const{
    if (!meaningful()){
        throw std::runtime_error("Error: Bad Key.");
    }

    return std::static_pointer_cast <Packet::Key> (packets[0]) -> get_keyid();
}

std::string Key::fingerprint() const{
    if (!meaningful()){
        throw std::runtime_error("Error: Bad Key.");
    }

    return std::static_pointer_cast <Packet::Key> (packets[0]) -> get_fingerprint();
}

uint8_t Key::version() const{
    if (!meaningful()){
        throw std::runtime_error("Error: Bad Key.");
    }

    return std::static_pointer_cast <Packet::Key> (packets[0]) -> get_version();
}

// output style inspired by gpg and SKS Keyserver/pgp.mit.edu
std::string Key::list_keys(const std::size_t indents, const std::size_t indent_size) const{
    if (!meaningful()){
        // "Error: Key data not meaningful.\n";
        return "";
    }

    const std::string indent(indents * indent_size, ' ');

    // print Key and User packets
    std::stringstream out;
    for(Packet::Tag::Ptr const & p : packets){
        // primary key/subkey
        if (Packet::is_key_packet(p -> get_tag())){
            const Packet::Key::Ptr key = std::static_pointer_cast <Packet::Key> (p);

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
                << indent << "uid " << std::static_pointer_cast <Packet::Tag13> (p) -> get_contents();
        }
        // User Attribute
        else if (p -> get_tag() == Packet::USER_ATTRIBUTE){
            for(Subpacket::Tag17::Sub::Ptr const & s : std::static_pointer_cast <Packet::Tag17> (p) -> get_attributes()){
                // since only subpacket type 1 is defined
                out << "\n"
                    << indent << "att  att  [jpeg image of size " << std::static_pointer_cast <Subpacket::Tag17::Sub1> (s) -> get_image().size() << "]";
            }
        }
        // Signature
        else if (p -> get_tag() == Packet::SIGNATURE){
            out << indent << "sig ";

            const Packet::Tag2::Ptr sig = std::static_pointer_cast <Packet::Tag2> (p);
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

Key::pkey Key::get_pkey() const{
    if (!meaningful()){
        throw std::runtime_error("Error: Bad Key.");
    }
    pkey pk;
    pk.key = packets[0];
    Packet::Tag::Ptr lastUser_userAtt = nullptr;
    Packet::Tag::Ptr lastUserID = nullptr;
    Packet::Tag::Ptr lastSubkey = nullptr;
    for(Packets::size_type i = 1; i < packets.size(); i++){
        switch(packets[i]->get_tag()){
            case Packet::SIGNATURE:
                if (!lastUser_userAtt && !lastSubkey){
                    pk.keySigs.insert(std::make_pair(pk.key, packets[i]));
                }
                else if (lastUser_userAtt && !lastSubkey){
                    pk.uids.insert(std::make_pair(lastUser_userAtt, packets[i]));
                }
                else if (!lastUser_userAtt && lastSubkey){
                    pk.subKeys.insert(std::make_pair(lastSubkey, packets[i]));
                }
                else{ // this should never happen
                    throw std::logic_error("Some subkey lost during merge");
                }
                break;
            case Packet::USER_ATTRIBUTE:
                if (!lastUserID){
                    throw std::runtime_error("User attribute found without a UserID packet");
                }
                pk.uid_userAtt.insert(std::make_pair(lastUserID, packets[i]));
                lastUser_userAtt = packets[i];
                lastSubkey = nullptr;
                break;
            case Packet::USER_ID:
                pk.uid_list.push_back(packets[i]);
                lastUserID = packets[i];
                lastUser_userAtt = packets[i];
                lastSubkey = nullptr;
                break;
            case Packet::SECRET_SUBKEY:
            case Packet::PUBLIC_SUBKEY:
                lastUser_userAtt = nullptr;
                lastUserID = nullptr;
                lastSubkey = packets[i];
                break;
            default:
                throw std::runtime_error("Packet not recognized during merge");
                // break;
        }
    }
    return pk;
}

bool Key::meaningful(const PGP & pgp){
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
        // "Error: Bad key type: " + std::to_string(pgp.get_type()) + "\n";
        return false;
    }

    const Packets & packets = pgp.get_packets();

    // minimum 2 packets: Primary Key + User ID
    if (packets.size() < 2){
        // "Error: Not enough packets (minimum 2).\n";
        return false;
    }

    //   - One Public/Secret-Key packet
    if (packets[0] -> get_tag() != key){
        // "Error: First packet is not a " + Packet::NAME.at(key) + ".\n";
        return false;
    }

    // get version of primary key
    const uint8_t primary_key_version = std::static_pointer_cast <Packet::Key> (packets[0]) -> get_version();

    //   - Zero or more revocation signatures
    unsigned int i = 1;
    while ((i < packets.size()) && (packets[i] -> get_tag() == Packet::SIGNATURE)){
        if (std::static_pointer_cast <Packet::Tag2> (packets[i]) -> get_type() == Signature_Type::KEY_REVOCATION_SIGNATURE){
            // "Warning: Revocation Signature found on primary key.\n";
            i++;
        }
        else{
            // "Error: Packet " + std::to_string(i) + " following " + Packet::NAME.at(key) + " is not a key revocation signature.\n";
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
    Packet::Tag13::Ptr user_id = nullptr;
    do{
        // make sure there is a User packet
        if ((packets[i] -> get_tag() != Packet::USER_ID)       &&
            (packets[i] -> get_tag() != Packet::USER_ATTRIBUTE)){
            // "Error: Packet is not a User ID or User Attribute Packet.\n";
            return false;
        }

        const Packet::User::Ptr user = std::static_pointer_cast <Packet::User> (packets[i]);
        if (user -> get_tag() == Packet::USER_ID){
            user_id = std::static_pointer_cast <Packet::Tag13> (user);
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
            const Packet::Tag2::Ptr sig = std::static_pointer_cast <Packet::Tag2> (packets[i]);
            if (!Signature_Type::is_certification(sig -> get_type())){
                // User IDs can have revocation signatures
                if ((user -> get_tag() == Packet::USER_ID) &&
                    (sig -> get_type() == Signature_Type::CERTIFICATION_REVOCATION_SIGNATURE)){
                    // "Warning: Revocation Signature found on UID.\n";
                }
                else{
                    // "Error: Signature is not a certification or revocation.\n";
                    return false;
                }
            }

            i++;
        }
    } while ((i < packets.size()) &&
             (Packet::is_user(packets[i] -> get_tag())));

    // need at least one User ID packet
    if (!user_id){
        // "Error: Need at least one " + Packet::NAME.at(Packet::USER_ID) + ".\n";
        return false;
    }

    //    - Zero or more Subkey packets
    while (i < packets.size()){
        if  (packets[i] -> get_tag() != subkey){
            // "Error: Bad subkey packet.\n";
            return false;
        }

        if (primary_key_version == 3){
            // "Error: Version 3 keys MUST NOT have subkeys.\n";
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
            const Packet::Tag2::Ptr sig = std::static_pointer_cast <Packet::Tag2> (packets[i]);
            if (sig -> get_type() == Signature_Type::SUBKEY_REVOCATION_SIGNATURE){
                // "Warning: Revocation Signature found on subkey.\n";
            }
            // at least one of the signatures should be a subkey binding signature (?)
            else if (sig -> get_type() == Signature_Type::SUBKEY_BINDING_SIGNATURE){
                subkey_binding = true;
            }

            i++;
        }

        if (!subkey_binding){
            // "Error: No " + Signature_Type::NAME.at(Signature_Type::SUBKEY_BINDING_SIGNATURE) + " packet found following subkey.\n";
            return false;
        }
    }

    // the index should be at the end of the packets
    return (i == packets.size());
}

bool Key::meaningful() const{
    return meaningful(*this);
}

Key::Packets Key::get_elements_by_key (const SigPairs::iterator first, const SigPairs::iterator last, const Packet::Tag::Ptr &key) const{
    Packets ps;
    for(SigPairs::iterator it = first; it != last; it++){
        if (it->first == key){
            ps.push_back(it->second);
        }
    }
    return ps;
}

void Key::merge(const Key::Ptr &k) {
    // Get pkey version from each key
    pkey pk1 = this->get_pkey();
    pkey pk2 = k->get_pkey();
    // Verify that the primary keys are equals
    if (pk1.key != pk2.key){
        throw std::runtime_error("Merge not possible between different keys");
    }

    // Join the sigpair list of the keys
    pk1.keySigs.insert(pk2.keySigs.begin(), pk2.keySigs.end());
    pk1.uids.insert(pk2.uids.begin(), pk2.uids.end());
    pk1.subKeys.insert(pk2.subKeys.begin(), pk2.subKeys.end());
    pk1.uid_userAtt.insert(pk2.uid_userAtt.begin(), pk2.uid_userAtt.end());
    pk1.uid_list.insert(pk1.uid_list.end(), pk2.uid_list.begin(), pk2.uid_list.end());

    // Building the new packets list extracting the packet from the joined sigpairs
    Packets new_packets;
    new_packets.push_back(pk1.key);
    for(std::pair<const Packet::Tag::Ptr, Packet::Tag::Ptr> ks: pk1.keySigs){
        if (std::find(new_packets.begin(), new_packets.end(), ks.second) == new_packets.end()){
            new_packets.push_back(ks.second);
        }
    }
    flatten(pk1.uids, &new_packets, pk1.uid_userAtt);
    // Inserting remaining userID (the one without signatures) and the relative user attributes
    for (const Packet::Tag::Ptr &p: pk1.uid_list){
        if (std::find(new_packets.begin(), new_packets.end(), p) == new_packets.end()){
            new_packets.push_back(p);
            // Insert the relative user attributes with its signatures
            Packets ua_list = get_elements_by_key(pk1.uid_userAtt.begin(), pk1.uid_userAtt.end(), p);
            for (const Packet::Tag::Ptr &ua: ua_list){
                if (std::find(new_packets.begin(), new_packets.end(), ua) == new_packets.end()){
                    new_packets.push_back(ua);

                    Packets ua_signatures = get_elements_by_key(pk1.uids.begin(), pk1.uids.end(), ua);
                    for (const Packet::Tag::Ptr &s: ua_signatures){
                        if (std::find(new_packets.begin(), new_packets.end(), s) == new_packets.end()){
                            new_packets.push_back(s);
                        }
                    }
                }
            }
        }
    }

    flatten(pk1.subKeys, &new_packets, pk1.uid_userAtt);

    // Set the new packets list
    set_packets(new_packets);

    if (!meaningful()){
        throw std::logic_error("Key no more meaningful after merge");
    }
}

void Key::flatten(SigPairs sp, Packets *np, SigPairs ua_table){
    for(SigPairs::iterator i = sp.begin(); i != sp.end(); i++){
        if (i->first->get_tag() == Packet::USER_ATTRIBUTE){
            // The user attribute is handled below
            continue;
        }
        if (std::find(np->begin(), np->end(), i->first) != np->end()){
            // if the packet is already in the list, it is already handled (with all the correlated signatures)
            continue;
        }

        // Push back the "key" of the map and get all the referred objects
        np->push_back(i->first);
        Packets elements = get_elements_by_key(sp.begin(), sp.end(), i->first);

        for(Packet::Tag::Ptr const &p : elements){
            // insert the referred object
            if (std::find(np->begin(), np->end(), p) == np->end()){
                np->push_back(p);
            }
        }

        if (i->first->get_tag() == Packet::USER_ID){
            Packets ua_list = get_elements_by_key(ua_table.begin(), ua_table.end(), i->first);
            for(Packet::Tag::Ptr const &ua: ua_list){
                if (std::find(np->begin(), np->end(), ua) == np->end()){
                    np->push_back(ua);

                    Packets ua_signatures = get_elements_by_key(sp.begin(), sp.end(), ua);
                    for (const Packet::Tag::Ptr &p: ua_signatures){
                        if (std::find(np->begin(), np->end(), p) == np->end()){
                            np->push_back(p);
                        }
                    }
                }
            }
        }
    }
}

PGP::Ptr Key::clone() const{
    return std::make_shared <Key> (*this);
}

std::ostream & operator<<(std::ostream & stream, const Key & pgp){
    stream << hexlify(pgp.keyid());
    return stream;
}

PublicKey::PublicKey()
    : Key()
{
    type = PUBLIC_KEY_BLOCK;
}

PublicKey::PublicKey(const PublicKey & copy)
    : Key(copy)
{}

PublicKey::PublicKey(const Key & copy)
    : Key(copy)
{}

PublicKey::PublicKey(const std::string & data)
    : Key(data)
{}

PublicKey::PublicKey(std::istream & stream)
    : Key(stream)
{}

PublicKey::PublicKey(const SecretKey & sec)
    : PublicKey(sec.get_public())
{}

PublicKey::~PublicKey(){}

bool PublicKey::meaningful() const{
    if (type != PUBLIC_KEY_BLOCK){
        // "Error: ASCII Armor type is not PUBLIC_KEY_BLOCK.\n";
        return false;
    }

    return Key::meaningful(*this);
}

PublicKey & PublicKey::operator=(const PublicKey & pub){
    armored = pub.armored;
    type = pub.type;
    keys = pub.keys;
    packets = pub.packets;

    for(Packet::Tag::Ptr & p : packets){
        p = p -> clone();
    }

    return *this;
}

PublicKey & PublicKey::operator=(const SecretKey & pri){
    return *this = pri.get_public();
}

PGP::Ptr PublicKey::clone() const{
    return std::make_shared <PublicKey> (*this);
}

std::ostream & operator<<(std::ostream & stream, const PublicKey & pgp){
    stream << hexlify(pgp.keyid());
    return stream;
}

SecretKey::SecretKey()
    : Key()
{
    type = PRIVATE_KEY_BLOCK;
}

SecretKey::SecretKey(const Key & copy)
    : Key(copy)
{}

SecretKey::SecretKey(const SecretKey & copy)
    : Key(copy)
{}

SecretKey::SecretKey(const std::string & data)
    : Key(data)
{}

SecretKey::SecretKey(std::istream & stream)
    : Key(stream)
{}

SecretKey::~SecretKey(){}

PublicKey SecretKey::get_public() const{
    PublicKey pub;
    pub.set_armored(armored);
    pub.set_type(PUBLIC_KEY_BLOCK);
    pub.set_keys(keys);

    // clone packets; convert secret packets into public ones
    Packets pub_packets;
    for(Packet::Tag::Ptr const & p : packets){
        if (p -> get_tag() == Packet::SECRET_KEY){
            pub_packets.push_back(std::static_pointer_cast <Packet::Tag5> (p) -> get_public_ptr());
        }
        else if (p -> get_tag() == Packet::SECRET_SUBKEY){
            pub_packets.push_back(std::static_pointer_cast <Packet::Tag7> (p) -> get_public_ptr());
        }
        else{
            pub_packets.push_back(p -> clone());
        }
    }

    pub.set_packets(pub_packets);

    return pub;
}

bool SecretKey::meaningful() const{
    if (type != PRIVATE_KEY_BLOCK){
        // "Error: ASCII Armor type is not PRIVATE_KEY_BLOCK.\n";
        return false;
    }

    return Key::meaningful(*this);
}

PGP::Ptr SecretKey::clone() const{
    return std::make_shared <SecretKey> (*this);
}

std::ostream & operator<<(std::ostream & stream, const SecretKey & pgp){
    stream << hexlify(pgp.keyid());
    return stream;
}

Packet::Key::Ptr find_signing_key(const Key & key){
    // if the key is not actually a key
    if (!key.meaningful()){
        return nullptr;
    }

    for(Packet::Tag::Ptr const & p : key.get_packets()){
        if (Packet::is_key_packet(p -> get_tag())){ // primary key or subkey
            Packet::Key::Ptr signing = std::static_pointer_cast <Packet::Key> (p);

            // make sure key has signing material
            if (PKA::can_sign(signing -> get_pka())){
                return signing;
            }
        }
    }

    return nullptr;
}

}

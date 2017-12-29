#include "Tag2.h"

namespace OpenPGP {
namespace Packet {

Tag2::Tag2()
    : Tag(SIGNATURE),
      type(0),
      pka(0),
      hash(0),
      mpi(),
      left16(),
      time(0),
      keyid(),
      hashed_subpackets(),
      unhashed_subpackets()
{}

Tag2::Tag2(const Tag2 & copy)
    : Tag(copy),
      type(copy.type),
      pka(copy.pka),
      hash(copy.hash),
      mpi(copy.mpi),
      left16(copy.left16),
      time(copy.time),
      keyid(copy.keyid),
      hashed_subpackets(copy.get_hashed_subpackets_clone()),
      unhashed_subpackets(copy.get_unhashed_subpackets_clone())
{}

Tag2::Tag2(const std::string & data)
    : Tag2()
{
    read(data);
}

Tag2::~Tag2(){
    hashed_subpackets.clear();
    unhashed_subpackets.clear();
}

// Extracts Subpacket data for figuring which subpacket type to create
void Tag2::read_subpacket(const std::string & data, std::string::size_type & pos, std::string::size_type & length){
    length = 0;

    const uint8_t first_octet = static_cast <unsigned char> (data[pos]);
    if (first_octet < 192){
        length = first_octet;
        pos += 1;
    }
    else if ((192 <= first_octet) && (first_octet < 255)){
        length = toint(data.substr(pos, 2), 256) - (192 << 8) + 192;
        pos += 2;
    }
    else if (first_octet == 255){
        length = toint(data.substr(pos + 1, 4), 256);
        pos += 5;
    }
}

void Tag2::read_subpackets(const std::string & data, Tag2::Subpackets & subpackets){
    subpackets.clear();
    std::string::size_type pos = 0;

    while (pos < data.size()){
        // read subpacket data out
        std::string::size_type length;
        read_subpacket(data, pos, length);  // pos moved past header to [length + data]

        Subpacket::Tag2::Sub::Ptr subpacket = nullptr;

        // first octet of data is subpacket type
        // ignore critical bit until later
        const uint8_t type = data[pos] & 0x7f;
        if (type == Subpacket::Tag2::SIGNATURE_CREATION_TIME){
            subpacket = std::make_shared <Subpacket::Tag2::Sub2> ();
        }
        else if (type == Subpacket::Tag2::SIGNATURE_EXPIRATION_TIME){
            subpacket = std::make_shared <Subpacket::Tag2::Sub3> ();
        }
        else if (type == Subpacket::Tag2::EXPORTABLE_CERTIFICATION){
            subpacket = std::make_shared <Subpacket::Tag2::Sub4> ();
        }
        else if (type == Subpacket::Tag2::TRUST_SIGNATURE){
            subpacket = std::make_shared <Subpacket::Tag2::Sub5> ();
        }
        else if (type == Subpacket::Tag2::REGULAR_EXPRESSION){
            subpacket = std::make_shared <Subpacket::Tag2::Sub6> ();
        }
        else if (type == Subpacket::Tag2::REVOCABLE){
            subpacket = std::make_shared <Subpacket::Tag2::Sub7> ();
        }
        else if (type == Subpacket::Tag2::KEY_EXPIRATION_TIME){
            subpacket = std::make_shared <Subpacket::Tag2::Sub9> ();
        }
        else if (type == Subpacket::Tag2::PLACEHOLDER_FOR_BACKWARD_COMPATIBILITY){
            subpacket = std::make_shared <Subpacket::Tag2::Sub10> ();
        }
        else if (type == Subpacket::Tag2::PREFERRED_SYMMETRIC_ALGORITHMS){
            subpacket = std::make_shared <Subpacket::Tag2::Sub11> ();
        }
        else if (type == Subpacket::Tag2::REVOCATION_KEY){
            subpacket = std::make_shared <Subpacket::Tag2::Sub12> ();
        }
        else if (type == Subpacket::Tag2::ISSUER){
            subpacket = std::make_shared <Subpacket::Tag2::Sub16> ();
        }
        else if (type == Subpacket::Tag2::NOTATION_DATA){
            subpacket = std::make_shared <Subpacket::Tag2::Sub20> ();
        }
        else if (type == Subpacket::Tag2::PREFERRED_HASH_ALGORITHMS){
            subpacket = std::make_shared <Subpacket::Tag2::Sub21> ();
        }
        else if (type == Subpacket::Tag2::PREFERRED_COMPRESSION_ALGORITHMS){
            subpacket = std::make_shared <Subpacket::Tag2::Sub22> ();
        }
        else if (type == Subpacket::Tag2::KEY_SERVER_PREFERENCES){
            subpacket = std::make_shared <Subpacket::Tag2::Sub23> ();
        }
        else if (type == Subpacket::Tag2::PREFERRED_KEY_SERVER){
            subpacket = std::make_shared <Subpacket::Tag2::Sub24> ();
        }
        else if (type == Subpacket::Tag2::PRIMARY_USER_ID){
            subpacket = std::make_shared <Subpacket::Tag2::Sub25> ();
        }
        else if (type == Subpacket::Tag2::POLICY_URI){
            subpacket = std::make_shared <Subpacket::Tag2::Sub26> ();
        }
        else if (type == Subpacket::Tag2::KEY_FLAGS){
            subpacket = std::make_shared <Subpacket::Tag2::Sub27> ();
        }
        else if (type == Subpacket::Tag2::SIGNERS_USER_ID){
            subpacket = std::make_shared <Subpacket::Tag2::Sub28> ();
        }
        else if (type == Subpacket::Tag2::REASON_FOR_REVOCATION){
            subpacket = std::make_shared <Subpacket::Tag2::Sub29> ();
        }
        else if (type == Subpacket::Tag2::FEATURES){
            subpacket = std::make_shared <Subpacket::Tag2::Sub30> ();
        }
        else if (type == Subpacket::Tag2::SIGNATURE_TARGET){
            subpacket = std::make_shared <Subpacket::Tag2::Sub31> ();
        }
        else if (type == Subpacket::Tag2::EMBEDDED_SIGNATURE){
            subpacket = std::make_shared <Subpacket::Tag2::Sub32> ();
        }
        #ifdef GPG_COMPATIBLE
        else if (type == Subpacket::Tag2::ISSUER_FINGERPRINT){
            subpacket = std::make_shared <Subpacket::Tag2::Sub33> ();
        }
        #endif
        else{
            throw std::runtime_error("Error: Tag 2 Subpacket tag not defined or reserved: " + std::to_string(type));
        }

        // subpacket guaranteed to be defined
        subpacket -> read(data.substr(pos + 1, length - 1));
        subpacket -> set_critical(data[pos] & 0x80);
        subpackets.push_back(subpacket);

        // go to end of current subpacket
        pos += length;
    }
}

void Tag2::read(const std::string & data){
    size = data.size();
    tag = 2;
    version = data[0];
    if (version < 4){
        if (data[1] != 5){
            throw std::runtime_error("Error: Length of hashed material must be 5.");
        }
        type   = data[2];
        time   = toint(data.substr(3, 4), 256);
        keyid  = data.substr(7, 8);

        pka    = data[15];
        hash   = data[16];
        left16 = data.substr(17, 2);
        std::string::size_type pos = 19;

        if (PKA::is_RSA(pka)){
            mpi.push_back(read_MPI(data, pos)); // RSA m**d mod n
        }
        #ifdef GPG_COMPATIBLE
        else if(pka == PKA::ID::DSA || pka == PKA::ID::ECDSA){
            mpi.push_back(read_MPI(data, pos)); // r
            mpi.push_back(read_MPI(data, pos)); // s
        }
        #else
        else if (pka == PKA::ID::DSA){
            mpi.push_back(read_MPI(data, pos)); // DSA r
            mpi.push_back(read_MPI(data, pos)); // DSA s
        }
        #endif
        else{
            throw std::runtime_error("Error: Unknown PKA type: " + std::to_string(pka));
        }
    }
    else if (version == 4){
        type = data[1];
        pka  = data[2];
        hash = data[3];

        // hashed subpackets
        const uint16_t hashed_size = toint(data.substr(4, 2), 256);
        read_subpackets(data.substr(6, hashed_size), hashed_subpackets);

        // unhashed subpacketss
        const uint16_t unhashed_size = toint(data.substr(hashed_size + 6, 2), 256);
        read_subpackets(data.substr(hashed_size + 6 + 2, unhashed_size), unhashed_subpackets);

        // get left 16 bits
        left16 = data.substr(hashed_size + 6 + 2 + unhashed_size, 2);

//        if (PKA::is_RSA(PKA))
        std::string::size_type pos = hashed_size + 6 + 2 + unhashed_size + 2;
        mpi.push_back(read_MPI(data, pos));         // RSA m**d mod n
        #ifdef GPG_COMPATIBLE
        if(pka == PKA::ID::DSA || pka == PKA::ID::ECDSA || pka == PKA::ID::EdDSA){
            // mpi.push_back(read_MPI(data, pos)); // r
            mpi.push_back(read_MPI(data, pos)); // s
        }
        #else
        if (pka == PKA::ID::DSA){
            // mpi.push_back(read_MPI(data, pos)); // DSA r
            mpi.push_back(read_MPI(data, pos)); // DSA s
        }
        #endif
    }
    else{
        throw std::runtime_error("Error: Tag2 Unknown version: " + std::to_string(static_cast <unsigned int> (version)));
    }
}

std::string Tag2::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    const decltype(Signature_Type::NAME)::const_iterator sigtype_it = Signature_Type::NAME.find(type);
    const decltype(PKA::NAME)::const_iterator pka_it = PKA::NAME.find(pka);
    const decltype(Hash::NAME)::const_iterator hash_it = Hash::NAME.find(hash);
    std::string out = indent + show_title() + "\n" +
                      indent + tab + "Version: " + std::to_string(version) + "\n";

    if (version < 4){
        out += indent + tab + "Hashed Material:\n" +
               indent + tab + tab + "Signature Type: " + ((sigtype_it == Signature_Type::NAME.end())?"Unknown":(sigtype_it -> second)) + " (type 0x" + makehex(type, 2) + ")\n" +
               indent + tab + tab + "Creation Time: " + show_time(time) + "\n" +
               indent + tab + "Signer's Key ID: " + hexlify(keyid) + "\n" +
               indent + tab + "Public Key Algorithm: " + ((pka_it == PKA::NAME.end())?"Unknown":(pka_it -> second)) + " (pka " + std::to_string(pka) + ")\n" +
               indent + tab + "Hash Algorithm: " + ((hash_it == Hash::NAME.end())?"Unknown":(hash_it -> second)) + " (hash " + std::to_string(hash) + ")\n";
    }
    else if (version == 4){
        out += indent + tab + "Signature Type: " + ((sigtype_it == Signature_Type::NAME.end())?"Unknown":(sigtype_it -> second)) + " (type 0x" + makehex(type, 2) + ")\n" +
               indent + tab + "Public Key Algorithm: " + ((pka_it == PKA::NAME.end())?"Unknown":(pka_it -> second)) + " (pka " + std::to_string(pka) + ")\n" +
               indent + tab + "Hash Algorithm: " + ((hash_it == Hash::NAME.end())?"Unknown":(hash_it -> second)) + " (hash " + std::to_string(hash) + ")";

        if (hashed_subpackets.size()){
            uint32_t create_time = 0;

            out += "\n" + indent + tab + "Hashed Sub:";
            for(Subpacket::Tag2::Sub::Ptr const & s : hashed_subpackets){
                // capture signature creation time to combine with expiration time
                if (s -> get_type() == Subpacket::Tag2::SIGNATURE_CREATION_TIME){
                    create_time = std::static_pointer_cast <Subpacket::Tag2::Sub2> (s) -> get_time();
                }

                if (s -> get_type() == Subpacket::Tag2::KEY_EXPIRATION_TIME){
                    out += "\n" + std::static_pointer_cast <Subpacket::Tag2::Sub9> (s) -> show(create_time, indents + 2, indent_size);
                }
                else{
                    out += "\n" + s -> show(indents + 2, indent_size);
                }
            }
        }

        if (unhashed_subpackets.size()){
            uint32_t create_time = 0;

            out += "\n" + indent + tab + "Unhashed Sub:";
            for(Subpacket::Tag2::Sub::Ptr const & s : unhashed_subpackets){
                // capture signature creation time to combine with expiration time
                if (s -> get_type() == Subpacket::Tag2::SIGNATURE_CREATION_TIME){
                    create_time = std::static_pointer_cast <Subpacket::Tag2::Sub2> (s) -> get_time();
                }

                if (s -> get_type() == Subpacket::Tag2::KEY_EXPIRATION_TIME){
                    out += "\n" + std::static_pointer_cast <Subpacket::Tag2::Sub9> (s) -> show(create_time, indents + 2, indent_size);
                }
                else{
                    out += "\n" + s -> show(indents + 2, indent_size);
                }
            }
        }
    }

    out += "\n" + indent + tab + "Hash Left 16 Bits: " + hexlify(left16);

    if (PKA::is_RSA(pka)){
        out += "\n" + indent + tab + "RSA m**d mod n (" + std::to_string(bitsize(mpi[0])) + " bits): " + mpitohex(mpi[0]);
    }
    #ifdef GPG_COMPATIBLE
    else if (pka == PKA::ID::ECDSA){
        out += "\n" + indent + tab + "ECDSA r (" + std::to_string(bitsize(mpi[0])) + " bits): " + mpitohex(mpi[0])
            += "\n" + indent + tab + "ECDSA s (" + std::to_string(bitsize(mpi[1])) + " bits): " + mpitohex(mpi[1]);
    }
    else if (pka == PKA::ID::EdDSA){
        out += "\n" + indent + tab + "EdDSA r (" + std::to_string(bitsize(mpi[0])) + " bits): " + mpitohex(mpi[0])
            += "\n" + indent + tab + "EdDSA s (" + std::to_string(bitsize(mpi[1])) + " bits): " + mpitohex(mpi[1]);
    }
    #endif
    else if (pka == PKA::ID::DSA){
        out += "\n" + indent + tab + "DSA r (" + std::to_string(bitsize(mpi[0])) + " bits): " + mpitohex(mpi[0])
            += "\n" + indent + tab + "DSA s (" + std::to_string(bitsize(mpi[1])) + " bits): " + mpitohex(mpi[1]);
    }

    return out;
}

std::string Tag2::raw() const{
    std::string out(1, version);
    if (version < 4){// to recreate older keys
        out += "\x05" + std::string(1, type) + unhexlify(makehex(time, 8)) + keyid + std::string(1, pka) + std::string(1, hash) + left16;
    }
    if (version == 4){
        std::string hashed_str = "";
        for(Subpacket::Tag2::Sub::Ptr const & s : hashed_subpackets){
            hashed_str += s -> write();
        }
        std::string unhashed_str = "";
        for(Subpacket::Tag2::Sub::Ptr const & s : unhashed_subpackets){
            unhashed_str += s -> write();
        }
        out += std::string(1, type) + std::string(1, pka) + std::string(1, hash) + unhexlify(makehex(hashed_str.size(), 4)) + hashed_str + unhexlify(makehex(unhashed_str.size(), 4)) + unhashed_str + left16;
    }
    for(MPI const & i : mpi){
        out += write_MPI(i);
    }
    return out;
}

uint8_t Tag2::get_type() const{
    return type;
}

uint8_t Tag2::get_pka() const{
    return pka;
}

uint8_t Tag2::get_hash() const{
    return hash;
}

std::string Tag2::get_left16() const{
    return left16;
}

PKA::Values Tag2::get_mpi() const{
    return mpi;
}

std::array <uint32_t, 3> Tag2::get_times() const{
    std::array <uint32_t, 3> times = {0, 0, 0};
    if (version == 3){
        times[0] = time;
    }
    else if (version == 4){
        // usually found in hashed subpackets
        for(Subpacket::Tag2::Sub::Ptr const & s : hashed_subpackets){
            // 5.2.3.4. Signature Creation Time
            //    ...
            //    MUST be present in the hashed area.
            if (s -> get_type() == Subpacket::Tag2::SIGNATURE_CREATION_TIME){
                times[0] = std::static_pointer_cast <Subpacket::Tag2::Sub2> (s) -> get_time();
            }
            else if (s -> get_type() == Subpacket::Tag2::SIGNATURE_EXPIRATION_TIME){
                times[1] = std::static_pointer_cast <Subpacket::Tag2::Sub3> (s) -> get_dt();
            }
            else if (s -> get_type() == Subpacket::Tag2::KEY_EXPIRATION_TIME){
                times[2] = std::static_pointer_cast <Subpacket::Tag2::Sub9> (s) -> get_dt();
            }
        }

        // search unhashed subpackets
        for(Subpacket::Tag2::Sub::Ptr const & s : unhashed_subpackets){
            if (s -> get_type() == Subpacket::Tag2::SIGNATURE_EXPIRATION_TIME){
                times[1] = std::static_pointer_cast <Subpacket::Tag2::Sub3> (s) -> get_dt();
            }
            else if (s -> get_type() == Subpacket::Tag2::KEY_EXPIRATION_TIME){
                times[2] = std::static_pointer_cast <Subpacket::Tag2::Sub9> (s) -> get_dt();
            }
        }

        if (!times[0]){
            throw std::runtime_error("Error: No signature creation time found.\n");
        }

        if (times[1]){
            times[1] += times[0];
        }

        if (times[2]){
            times[2] += times[0];
        }
    }
    else{
        throw std::runtime_error("Error: Signature Packet version " + std::to_string(version) + " not defined.");
    }

    return times;
}

std::string Tag2::get_keyid() const{
    if (version == 3){
        return keyid;
    }
    else if (version == 4){
        // usually found in unhashed subpackets
        for(Subpacket::Tag2::Sub::Ptr const & s : unhashed_subpackets){
            if (s -> get_type() == Subpacket::Tag2::ISSUER){
                return std::static_pointer_cast <Subpacket::Tag2::Sub16> (s) -> get_keyid();
            }
        }

        // search hashed subpackets if necessary
        for(Subpacket::Tag2::Sub::Ptr const & s : hashed_subpackets){
            if (s -> get_type() == Subpacket::Tag2::ISSUER){
                return std::static_pointer_cast <Subpacket::Tag2::Sub16> (s) -> get_keyid();
            }
        }
    }
    else{
        throw std::runtime_error("Error: Signature Packet version " + std::to_string(version) + " not defined.");
    }

    return ""; // should never reach here; mainly just to remove compiler warnings
}

Tag2::Subpackets Tag2::get_hashed_subpackets() const{
    return hashed_subpackets;
}

Tag2::Subpackets Tag2::get_hashed_subpackets_clone() const{
    Subpackets out;
    for(Subpacket::Tag2::Sub::Ptr const & s : hashed_subpackets){
        out.push_back(s -> clone());
    }
    return out;
}

Tag2::Subpackets Tag2::get_unhashed_subpackets() const{
    return unhashed_subpackets;
}

Tag2::Subpackets Tag2::get_unhashed_subpackets_clone() const{
    Subpackets out;
    for(Subpacket::Tag2::Sub::Ptr const & s : unhashed_subpackets){
        out.push_back(s -> clone());
    }
    return out;
}

std::string Tag2::get_up_to_hashed() const{
    if (version == 3){
        return "\x03" + std::string(1, type) + unhexlify(makehex(time, 8));
    }
    else if (version == 4){
        std::string hashed = "";
        for(Subpacket::Tag2::Sub::Ptr const & s : hashed_subpackets){
            hashed += s -> write();
        }
        return "\x04" + std::string(1, type) + std::string(1, pka) + std::string(1, hash) + unhexlify(makehex(hashed.size(), 4)) + hashed;
    }
    else{
        throw std::runtime_error("Error: Signature packet version " + std::to_string(version) + " not defined.");
    }
    return ""; // should never reach here; mainly just to remove compiler warnings
}

std::string Tag2::get_without_unhashed() const{
    std::string out(1, version);
    if (version < 4){// to recreate older keys
        out += "\x05" + std::string(1, type) + unhexlify(makehex(time, 8)) + keyid + std::string(1, pka) + std::string(1, hash) + left16;
    }
    if (version == 4){
        std::string hashed_str = "";
        for(Subpacket::Tag2::Sub::Ptr const & s : hashed_subpackets){
            hashed_str += s -> write();
        }
        out += std::string(1, type) + std::string(1, pka) + std::string(1, hash) + unhexlify(makehex(hashed_str.size(), 4)) + hashed_str + zero + zero + left16;
    }
    for(MPI const & i : mpi){
        out += write_MPI(i);
    }
    return out;
}

void Tag2::set_type(const uint8_t t){
    type = t;
    size = raw().size();
}

void Tag2::set_pka(const uint8_t p){
    pka = p;
    size = raw().size();
}

void Tag2::set_hash(const uint8_t h){
    hash = h;
    size = raw().size();
}

void Tag2::set_left16(const std::string & l){
    left16 = l;
    size = raw().size();
}

void Tag2::set_mpi(const PKA::Values & m){
    mpi = m;
    size = raw().size();
}

void Tag2::set_time(const uint32_t t){
    if (version == 3){
        time = t;
    }
    else if (version == 4){
        unsigned int i;
        for(i = 0; i < hashed_subpackets.size(); i++){
            if (hashed_subpackets[i] -> get_type() == 2){
                break;
            }
        }
        Subpacket::Tag2::Sub2::Ptr sub2 = std::make_shared <Subpacket::Tag2::Sub2> ();
        sub2 -> set_time(t);
        if (i == hashed_subpackets.size()){ // not found
            hashed_subpackets.push_back(sub2);
        }
        else{                               // found
            hashed_subpackets[i] = sub2;
        }
    }
    size = raw().size();
}

void Tag2::set_keyid(const std::string & k){
    if (k.size() != 8){
        throw std::runtime_error("Error: Key ID must be 8 octets.");
    }

    if (version == 3){
        keyid = k;
    }
    else if (version == 4){
        unsigned int i;
        for(i = 0; i < unhashed_subpackets.size(); i++){
            if (unhashed_subpackets[i] -> get_type() == 16){
                break;
            }
        }
        Subpacket::Tag2::Sub16::Ptr sub16 = std::make_shared <Subpacket::Tag2::Sub16> ();
        sub16 -> set_keyid(k);
        if (i == unhashed_subpackets.size()){   // not found
            unhashed_subpackets.push_back(sub16);
        }
        else{                                   // found
            unhashed_subpackets[i] = sub16;
        }
    }
    size = raw().size();
}

void Tag2::set_hashed_subpackets(const Tag2::Subpackets & h){
    hashed_subpackets.clear();
    for(Subpacket::Tag2::Sub::Ptr const & s : h){
        hashed_subpackets.push_back(s -> clone());
    }
    size = raw().size();
}

void Tag2::set_unhashed_subpackets(const Tag2::Subpackets & u){
    unhashed_subpackets.clear();
    for(Subpacket::Tag2::Sub::Ptr const & s : u){
        unhashed_subpackets.push_back(s -> clone());
    }
    size = raw().size();
}

std::string Tag2::find_subpacket(const uint8_t sub) const{
    // 5.2.4.1. Subpacket Hints
    //
    //   It is certainly possible for a signature to contain conflicting
    //   information in subpackets. For example, a signature may contain
    //   multiple copies of a preference or multiple expiration times. In
    //   most cases, an implementation SHOULD use the last subpacket in the
    //   signature, but MAY use any conflict resolution scheme that makes
    //   more sense.

    std::string out;
    for(Subpacket::Tag2::Sub::Ptr const & s : hashed_subpackets){
        if (s -> get_type() == sub){
            out = s -> raw();
            break;
        }
    }
    for(Subpacket::Tag2::Sub::Ptr const & s : unhashed_subpackets){
        if (s -> get_type() == sub){
            out = s -> raw();
            break;
        }
    }
    return out;
}

Tag::Ptr Tag2::clone() const{
    Ptr out = std::make_shared <Tag2> (*this);
    out -> hashed_subpackets = get_hashed_subpackets_clone();
    out -> unhashed_subpackets = get_unhashed_subpackets_clone();
    return out;
}

Tag2 & Tag2::operator=(const Tag2 & copy){
    Tag::operator=(copy);
    type = copy.type;
    pka = copy.pka;
    hash = copy.hash;
    mpi = copy.mpi;
    left16 = copy.left16;
    time = copy.time;
    keyid = copy.keyid;
    hashed_subpackets = copy.get_hashed_subpackets_clone();
    unhashed_subpackets = copy.get_unhashed_subpackets_clone();
    return *this;
}

}
}
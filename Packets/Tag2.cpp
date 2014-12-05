#include "Tag2.h"

Tag2::Tag2():
    Packet(2),
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

Tag2::Tag2(const Tag2 & copy):
    Packet(copy),
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

Tag2::Tag2(std::string & data):
    Tag2()
{
    read(data);
}

Tag2::~Tag2(){
    hashed_subpackets.clear();
    unhashed_subpackets.clear();
}

// Extracts Subpacket data for figuring which subpacket type to create
// Some data is consumed in the process
std::string Tag2::read_subpacket(std::string & data){
    uint32_t length = 0;
    uint8_t first_octet = static_cast <unsigned char> (data[0]);
    if (first_octet < 192){
        length = first_octet;
        data = data.substr(1, data.size() - 1);
    }
    else if ((192 <= first_octet) && (first_octet < 255)){
        length = toint(data.substr(0, 2), 256) - (192 << 8) + 192;
        data = data.substr(2, data.size() - 2);
    }
    else if (first_octet == 255){
        length = toint(data.substr(1, 4), 256);
        data = data.substr(5, data.size() - 5);
    }
    std::string out = data.substr(0, length);                   // includes subpacket type
    data = data.substr(length, data.size() - length);           // remove subpacket from main data
    return out;
}

std::vector <Tag2Subpacket::Ptr> Tag2::read_subpackets(std::string & data){
    std::vector <Tag2Subpacket::Ptr> out;
    while (data.size()){
        Tag2Subpacket::Ptr temp;
        std::string subpacket_data = read_subpacket(data);
        uint8_t sub = subpacket_data[0];
        subpacket_data = subpacket_data.substr(1, subpacket_data.size() - 1);
        switch (sub){
            // reserved sub values will crash the program
            case 2:
                temp = std::make_shared<Tag2Sub2>();
                break;
            case 3:
                temp = std::make_shared<Tag2Sub3>();
                break;
            case 4:
                temp = std::make_shared<Tag2Sub4>();
                break;
            case 5:
                temp = std::make_shared<Tag2Sub5>();
                break;
            case 6:
                temp = std::make_shared<Tag2Sub6>();
                break;
            case 9:
                temp = std::make_shared<Tag2Sub9>();
                break;
            case 10:
                temp = std::make_shared<Tag2Sub10>();
                break;
            case 11:
                temp = std::make_shared<Tag2Sub11>();
                break;
            case 12:
                temp = std::make_shared<Tag2Sub12>();
                break;
            case 16:
                temp = std::make_shared<Tag2Sub16>();
                break;
            case 20:
                temp = std::make_shared<Tag2Sub20>();
                break;
            case 21:
                temp = std::make_shared<Tag2Sub21>();
                break;
            case 22:
                temp = std::make_shared<Tag2Sub22>();
                break;
            case 23:
                temp = std::make_shared<Tag2Sub23>();
                break;
            case 24:
                temp = std::make_shared<Tag2Sub24>();
                break;
            case 25:
                temp = std::make_shared<Tag2Sub25>();
                break;
            case 26:
                temp = std::make_shared<Tag2Sub26>();
                break;
            case 27:
                temp = std::make_shared<Tag2Sub27>();
                break;
            case 28:
                temp = std::make_shared<Tag2Sub28>();
                break;
            case 29:
                temp = std::make_shared<Tag2Sub29>();
                break;
            case 30:
                temp = std::make_shared<Tag2Sub30>();
                break;
            case 31:
                temp = std::make_shared<Tag2Sub31>();
                break;
            case 32:
                temp = std::make_shared<Tag2Sub32>();
                break;
            default:
                std::cerr << "Error: Unknown subpacket tag: " << static_cast <unsigned int> (sub) << " Ignoring." << std::endl;
                continue;
                break;
        }
        temp -> read(subpacket_data);
        out.push_back(temp);
    }
    return out;
}

void Tag2::read(std::string & data, const uint8_t part){
    size = data.size();
    tag = 2;
    version = data[0];
    if (version < 4){
        if (data[1] != 5){
            throw std::runtime_error("Error: Length of hashed material must be 5.");
        }
        type = data[2];
        time = toint(data.substr(3, 4), 256);
        keyid = data.substr(7, 8);

        pka = data[15];
        hash = data[16];
        left16 = data.substr(17, 2);
        data = data.substr(19, data.size() - 19);
        if (pka < 4){
            mpi.push_back(read_MPI(data));              // RSA m**d mod n
        }
        if (pka == 17){
            mpi.push_back(read_MPI(data));              // DSA r
            mpi.push_back(read_MPI(data));              // DSA s
        }
    }
    else if (version == 4){
        type = data[1];
        pka = data[2];
        hash = data[3];
        uint16_t hashed_size = toint(data.substr(4, 2), 256);
        data = data.substr(6, data.size() - 6);

        // hashed subpackets
        std::string hashed = data.substr(0, hashed_size);
        data = data.substr(hashed_size, data.size() - hashed_size);
        hashed_subpackets = read_subpackets(hashed);

        // unhashed subpacketss
        uint16_t unhashed_size = toint(data.substr(0, 2), 256);
        data = data.substr(2, data.size() - 2);
        std::string unhashed = data.substr(0, unhashed_size);
        data = data.substr(unhashed_size, data.size() - unhashed_size);
        unhashed_subpackets = read_subpackets(unhashed);

        left16 = data.substr(0, 2);
        data = data.substr(2, data.size() - 2);

//        if (pka < 4)
        mpi.push_back(read_MPI(data));              // RSA m**d mod n
        if (pka == 17){
//            mpi.push_back(read_MPI(data));        // DSA r
            mpi.push_back(read_MPI(data));          // DSA s
        }
    }
    else{
        std::stringstream s; s << static_cast <unsigned int> (version);
        throw std::runtime_error("Error: Tag2 Unknown version: " + s.str());
    }
}

std::string Tag2::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::stringstream out;
    out << std::string(tab, ' ') << show_title() << "\n"
        << std::string(tab, ' ') << "    Version: " << static_cast <unsigned int> (version) << "\n";
    if (version < 4){
        out << std::string(tab, ' ') << "    Hashed Material:\n"
            << std::string(tab, ' ') << "        Signature Type: " << Signature_Types.at(type) << " (type 0x" << makehex(type, 2) << ")\n"
            << std::string(tab, ' ') << "        Creation Time: " << show_time(time) << "\n"
            << std::string(tab, ' ') << "    Signer's Key ID: " << hexlify(keyid) << "\n"
            << std::string(tab, ' ') << "    Public Key Algorithm: " << Public_Key_Algorithms.at(pka) << " (pka " << static_cast <unsigned int> (pka) << ")\n"
            << std::string(tab, ' ') << "    Hash Algorithm: " << Hash_Algorithms.at(hash) << " (hash " << static_cast <unsigned int> (hash) << ")\n";
    }
    if (version == 4){
        out << std::string(tab, ' ') << "    Signature Type: " << Signature_Types.at(type) << " (type 0x" << makehex(type, 2) << ")\n"
            << std::string(tab, ' ') << "    Public Key Algorithm: " << Public_Key_Algorithms.at(pka) << " (pka " << static_cast <unsigned int> (pka) << ")\n"
            << std::string(tab, ' ') << "    Hash Algorithm: " << Hash_Algorithms.at(hash) << " (hash " << static_cast <unsigned int> (hash) << ")";

        if (hashed_subpackets.size()){
            out << "\n" << std::string(tab, ' ') << "    Hashed Sub:";
            for(Tag2Subpacket::Ptr const & s : hashed_subpackets){
                out << "\n" << s -> show(indents, indent_size);
            }
        }
        if (unhashed_subpackets.size()){
            out << "\n" << std::string(tab, ' ') << "    Unhashed Sub:";
            for(Tag2Subpacket::Ptr const & s : unhashed_subpackets){
                out << "\n" << s -> show(indents, indent_size);
            }
        }
    }
    out << "\n" << std::string(tab, ' ') << "    Hash Left 16 Bits: " << hexlify(left16);
    if (pka < 4){
        out << "\n" << std::string(tab, ' ') << "    RSA m**d mod n (" << bitsize(mpi[0]) << " bits): " << mpitohex(mpi[0]);
    }
    else if (pka == 17){
        out << "\n" << std::string(tab, ' ') << "    DSA r (" << bitsize(mpi[0]) << " bits): " << mpitohex(mpi[0])
            << "\n" << std::string(tab, ' ') << "    DSA s (" << bitsize(mpi[1]) << " bits): " << mpitohex(mpi[1]);
    }
    return out.str();
}

std::string Tag2::raw() const{
    std::string out(1, version);
    if (version < 4){// to recreate older keys
        out += "\x05" + std::string(1, type) + unhexlify(makehex(time, 8)) + keyid + std::string(1, pka) + std::string(1, hash) + left16;
    }
    if (version == 4){
        std::string hashed_str = "";
        for(Tag2Subpacket::Ptr const & s : hashed_subpackets){
            hashed_str += s -> write();
        }
        std::string unhashed_str = "";
        for(Tag2Subpacket::Ptr const & s : unhashed_subpackets){
            unhashed_str += s -> write();
        }
        out += std::string(1, type) + std::string(1, pka) + std::string(1, hash) + unhexlify(makehex(hashed_str.size(), 4)) + hashed_str + unhexlify(makehex(unhashed_str.size(), 4)) + unhashed_str + left16;
    }
    for(PGPMPI const & i : mpi){
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

std::vector <PGPMPI> Tag2::get_mpi() const{
    return mpi;
}

uint32_t Tag2::get_time() const{
    if (version == 3){
        return time;
    }
    else if (version == 4){
        for(Subpacket::Ptr const & s : hashed_subpackets){
            if (s -> get_type() == 2){
                std::string data = s -> raw();
                Tag2Sub2 sub2(data);
                return sub2.get_time();
            }
        }
    }
    return 0;
}

std::string Tag2::get_keyid() const{
    if (version == 3){
        return keyid;
    }
    else if (version == 4){
        // usually found in unhashed subpackets
        for(Tag2Subpacket::Ptr const & s : unhashed_subpackets){
            if (s -> get_type() == 16){
                std::string data = s -> raw();
                Tag2Sub16 sub16(data);
                return sub16.get_keyid();
            }
        }
        // search hashed subpackets if necessary
        for(Tag2Subpacket::Ptr const & s : hashed_subpackets){
            if (s -> get_type() == 16){
                std::string data = s -> raw();
                Tag2Sub16 sub16(data);
                return sub16.get_keyid();
            }
        }
    }
    else{
        std::stringstream s; s << static_cast <unsigned int> (version);
        throw std::runtime_error("Error: Signature Packet version " + s.str() + " not defined.");
    }
    return ""; // should never reach here; mainly just to remove compiler warnings
}

std::vector <Tag2Subpacket::Ptr> Tag2::get_hashed_subpackets() const{
    return hashed_subpackets;
}

std::vector <Tag2Subpacket::Ptr> Tag2::get_hashed_subpackets_clone() const{
    std::vector <Tag2Subpacket::Ptr> out;
    for(Tag2Subpacket::Ptr const & s : hashed_subpackets){
        out.push_back(s -> clone());
    }
    return out;
}

std::vector <Tag2Subpacket::Ptr> Tag2::get_unhashed_subpackets() const{
    return unhashed_subpackets;
}

std::vector <Tag2Subpacket::Ptr> Tag2::get_unhashed_subpackets_clone() const{
    std::vector <Tag2Subpacket::Ptr> out;
    for(Tag2Subpacket::Ptr const & s : unhashed_subpackets){
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
        for(Subpacket::Ptr const & s : hashed_subpackets){
            hashed += s -> write();
        }
        return "\x04" + std::string(1, type) + std::string(1, pka) + std::string(1, hash) + unhexlify(makehex(hashed.size(), 4)) + hashed;
    }
    else{
        std::stringstream s; s << static_cast <unsigned int> (version);
        throw std::runtime_error("Error: Signature packet version " + s.str() + " not defined.");
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
        for(Subpacket::Ptr const & s : hashed_subpackets){
            hashed_str += s -> write();
        }
        out += std::string(1, type) + std::string(1, pka) + std::string(1, hash) + unhexlify(makehex(hashed_str.size(), 4)) + hashed_str + zero + zero + left16;
    }
    for(PGPMPI const & i : mpi){
        out += write_MPI(i);
    }
    return out;
}

void Tag2::set_pka(const uint8_t p){
    pka = p;
    size = raw().size();
}

void Tag2::set_type(const uint8_t t){
    type = t;
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

void Tag2::set_mpi(const std::vector <PGPMPI> & m){
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
        Tag2Sub2::Ptr sub2 = std::make_shared<Tag2Sub2>();
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
        Tag2Sub16::Ptr sub16 = std::make_shared<Tag2Sub16>();
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

void Tag2::set_hashed_subpackets(const std::vector <Tag2Subpacket::Ptr> & h){
    hashed_subpackets.clear();
    for(Tag2Subpacket::Ptr const & s : h){
        hashed_subpackets.push_back(s -> clone());
    }
    size = raw().size();
}

void Tag2::set_unhashed_subpackets(const std::vector <Tag2Subpacket::Ptr> & u){
    unhashed_subpackets.clear();
    for(Tag2Subpacket::Ptr const & s : u){
        unhashed_subpackets.push_back(s -> clone());
    }
    size = raw().size();
}

std::string Tag2::find_subpacket(const uint8_t sub) const{
    /*
    5.2.4.1. Subpacket Hints

        It is certainly possible for a signature to contain conflicting
        information in subpackets. For example, a signature may contain
        multiple copies of a preference or multiple expiration times. In
        most cases, an implementation SHOULD use the last subpacket in the
        signature, but MAY use any conflict resolution scheme that makes
        more sense.
    */

    std::string out;
    for(Tag2Subpacket::Ptr const & s : hashed_subpackets){
        if (s -> get_type() == sub){
            out = s -> raw();
            break;
        }
    }
    for(Tag2Subpacket::Ptr const & s : unhashed_subpackets){
        if (s -> get_type() == sub){
            out = s -> raw();
            break;
        }
    }
    return out;
}

Packet::Ptr Tag2::clone() const{
    Ptr out = std::make_shared <Tag2> (*this);
    out -> hashed_subpackets = get_hashed_subpackets_clone();
    out -> unhashed_subpackets = get_unhashed_subpackets_clone();
    return out;
}

Tag2 & Tag2::operator =(const Tag2 & copy){
    Packet::operator =(copy);
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

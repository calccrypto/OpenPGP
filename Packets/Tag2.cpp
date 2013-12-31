#include "Tag2.h"
Tag2::Tag2(){
    tag = 2;
}

Tag2::Tag2(const Tag2 & tag2){
    tag = tag2.tag;
    version = tag2.version;
    format = tag2.format;
    size = tag2.size;
    type = tag2.type;
    pka = tag2.pka;
    hash = tag2.hash;
    mpi = tag2.mpi;
    left16 = tag2.left16;
    time = tag2.time;
    keyid = tag2.keyid;
    hashed_subpackets = get_hashed_subpackets_clone();
    unhashed_subpackets = get_unhashed_subpackets_clone();
}

Tag2::Tag2(std::string & data){
    tag = 2;
    read(data);
}

Tag2::~Tag2(){
    for(Subpacket *& s : hashed_subpackets){
        delete s;
    }
    hashed_subpackets.clear();
    for(Subpacket *& s : unhashed_subpackets){
        delete s;
    }
    unhashed_subpackets.clear();
}
// Extracts Subpacket data for figuring which subpacket type to create
// Some data is destroyed in the process
std::string Tag2::read_subpacket(std::string & data){
    uint32_t length = 0;
    uint8_t first_octet = (unsigned char) data[0];
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

std::vector <Subpacket *> Tag2::read_subpackets(std::string & data){
    std::vector <Subpacket *> out;
    while (data.size()){
        Subpacket * temp;
        std::string subpacket_data = read_subpacket(data);
        uint8_t sub = subpacket_data[0];
        subpacket_data = subpacket_data.substr(1, subpacket_data.size() - 1);
        switch (sub){
            // reserved sub values will crash the program
            case 2:
                temp = new Tag2Sub2;
                break;
            case 3:
                temp = new Tag2Sub3;
                break;
            case 4:
                temp = new Tag2Sub4;
                break;
            case 5:
                temp = new Tag2Sub5;
                break;
            case 6:
                temp = new Tag2Sub6;
                break;
            case 9:
                temp = new Tag2Sub9;
                break;
            case 10:
                temp = new Tag2Sub10;
                break;
            case 11:
                temp = new Tag2Sub11;
                break;
            case 12:
                temp = new Tag2Sub12;
                break;
            case 16:
                temp = new Tag2Sub16;
                break;
            case 20:
                temp = new Tag2Sub20;
                break;
            case 21:
                temp = new Tag2Sub21;
                break;
            case 22:
                temp = new Tag2Sub22;
                break;
            case 23:
                temp = new Tag2Sub23;
                break;
            case 24:
                temp = new Tag2Sub24;
                break;
            case 25:
                temp = new Tag2Sub25;
                break;
            case 26:
                temp = new Tag2Sub26;
                break;
            case 27:
                temp = new Tag2Sub27;
                break;
            case 28:
                temp = new Tag2Sub28;
                break;
            case 29:
                temp = new Tag2Sub29;
                break;
            case 30:
                temp = new Tag2Sub30;
                break;
            case 31:
                temp = new Tag2Sub31;
                break;
            case 32:
                temp = new Tag2Sub32;
                break;
            default:
                std::cerr << "Error: Subpacket tag not defined or reserved." << std::endl;
                throw(1);
                break;
        }
        temp -> read(subpacket_data);
        out.push_back(temp);
    }
    return out;
}

void Tag2::read(std::string & data){
    size = data.size();
    tag = 2;
    version = data[0];
    if (version < 4){
        if (data[1] != 5){
            std::cerr << "Error: Length of hashed material must be 5." << std::endl;
            throw(1);
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
    if (version == 4){
        type = data[1];
        pka = data[2];
        hash = data[3];
        uint16_t hashed_size = toint(data.substr(4, 2), 256);
        data = data.substr(6, data.size() - 6);
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
}

std::string Tag2::show(){
    std::stringstream out;
    out << "    Version: " << (unsigned int) version << "\n";
    if (version < 4){
        out << "    Hashed Material:\n"
            << "        Signature Type: " << Signature_Types.at(type) << " (type 0x" << makehex(type, 2) << ")\n"
            << "        Creation Time: " << show_time(time) << "\n"
            << "    Signer's Key ID: " << hexlify(keyid) << "\n"
            << "    Public Key Algorithm: " << Public_Key_Algorithms.at(pka) << " (pka " << (unsigned int) pka << ")\n"
            << "    Hash Algorithm: " << Hash_Algorithms.at(hash) << " (hash " << (unsigned int) hash << ")\n";
    }
    if (version == 4){
        out << "    Signature Type: " << Signature_Types.at(type) << " (type 0x" << makehex(type, 2) << ")\n"
            << "    Public Key Algorithm: " << Public_Key_Algorithms.at(pka) << " (pka " << (unsigned int) pka << ")\n"
            << "    Hash Algorithm: " << Hash_Algorithms.at(hash) << " (hash " << (unsigned int) hash << ")\n";

        if (hashed_subpackets.size()){
            for(Subpacket *& s : hashed_subpackets){
                out << "        " << Subpacket_Tags.at(s -> get_type()) << " Subpacket (sub " << (int) s -> get_type() << ") (" << s -> get_size() << " bytes)\n" << s -> show();
            }
        }
        if (unhashed_subpackets.size()){
            out << "    Unhashed Sub: \n";
            for(Subpacket *& s : unhashed_subpackets){
                out << "        " << Subpacket_Tags.at(s -> get_type()) << " Subpacket (sub " << (int) s -> get_type() << ") (" << s -> get_size() << " bytes)\n" << s -> show();
            }
        }
    }
    out << "    Hash Left 2 Bytes: " << hexlify(left16) << "\n";
    if (pka < 4)
        out << "    RSA m**d mod n (" << mpi[0].get_str(2).size() << " bits): " << mpi[0].get_str(16) << "\n";
    else if (pka == 17){
        out << "    DSA r (" << mpi[0].get_str(2).size() << " bits): " << mpi[0].get_str(16) << "\n"
            << "    DSA s (" << mpi[1].get_str(2).size() << " bits): " << mpi[1].get_str(16) << "\n";
    }
    return out.str();
}

std::string Tag2::raw(){
    std::string out(1, version);
    if (version < 4){// to recreate older keys
        out += "\x05" + std::string(1, type) + unhexlify(makehex(time, 8)) + keyid + std::string(1, pka) + std::string(1, hash) + left16;
    }
    if (version == 4){
        std::string hashed_str = "";
        for(Subpacket *& s : hashed_subpackets){
            hashed_str += s -> write();
        }
        std::string unhashed_str = "";
        for(Subpacket *& s : unhashed_subpackets){
            unhashed_str += s -> write();
        }
        out += std::string(1, type) + std::string(1, pka) + std::string(1, hash) + unhexlify(makehex(hashed_str.size(), 4)) + hashed_str + unhexlify(makehex(unhashed_str.size(), 4)) + unhashed_str + left16;
    }
    for(mpz_class & i : mpi){
        out += write_MPI(i);
    }
    return out;
}

uint8_t Tag2::get_type(){
    return type;
}

uint8_t Tag2::get_pka(){
    return pka;
}

uint8_t Tag2::get_hash(){
    return hash;
}

std::string Tag2::get_left16(){
    return left16;
}

std::vector <mpz_class> Tag2::get_mpi(){
    return mpi;
}

uint32_t Tag2::get_time(){
    if (version == 3){
        return time;
    }
    else if (version == 4){
        for(Subpacket * s : hashed_subpackets){
            if (s -> get_type() == 2){
                std::string data = s -> raw();
                Tag2Sub2 sub2(data);
                return sub2.get_time();
            }
        }
    }
    return 0;
}

std::string Tag2::get_keyid(){
    if (version == 3){
        return keyid;
    }
    else if (version == 4){
        for(Subpacket * s : unhashed_subpackets){
            if (s -> get_type() == 16){
                std::string data = s -> raw();
                Tag2Sub16 sub16(data);
                return sub16.get_keyid();
            }
        }
    }
    else{
        std::cerr << "Error: Signature Packet version " << version << " not defined." << std::endl;
        throw(1);
    }
    return ""; // should never reach here; mainly just to remove compiler warnings
}

std::vector <Subpacket *> Tag2::get_hashed_subpackets(){
    return hashed_subpackets;
}

std::vector <Subpacket *> Tag2::get_hashed_subpackets_clone(){
    std::vector <Subpacket *> out;
    for(Subpacket *& s : hashed_subpackets){
        out.push_back(s -> clone());
    }
    return out;
}

std::vector <Subpacket *> Tag2::get_unhashed_subpackets(){
    return unhashed_subpackets;
}

std::vector <Subpacket *> Tag2::get_unhashed_subpackets_clone(){
    std::vector <Subpacket *> out;
    for(Subpacket *& s : unhashed_subpackets){
        out.push_back(s -> clone());
    }
    return out;
}

std::string Tag2::get_up_to_hashed(){
    if (version == 3){
        return "\x03" + std::string(1, type) + unhexlify(makehex(time, 8));
    }
    else if (version == 4){
        std::string hashed = "";
        for(Subpacket *& s : hashed_subpackets){
            hashed += s -> write();
        }
        return "\x04" + std::string(1, type) + std::string(1, pka) + std::string(1, hash) + unhexlify(makehex(hashed.size(), 4)) + hashed;
    }
    else{
        std::cerr << "Error: Signature packet version " << (int) version << " not defined." << std::endl;
        throw(1);
    }
    return ""; // should never reach here; mainly just to remove compiler warnings
}

std::string Tag2::get_without_unhashed(){
    std::string out(1, version);
    if (version < 4){// to recreate older keys
        out += "\x05" + std::string(1, type) + unhexlify(makehex(time, 8)) + keyid + std::string(1, pka) + std::string(1, hash) + left16;
    }
    if (version == 4){
        std::string hashed_str = "";
        for(Subpacket *& s : hashed_subpackets){
            hashed_str += s -> write();
        }
        out += std::string(1, type) + std::string(1, pka) + std::string(1, hash) + unhexlify(makehex(hashed_str.size(), 4)) + hashed_str + zero + zero + left16;
    }
    for(mpz_class & i : mpi){
        out += write_MPI(i);
    }
    return out;
}

void Tag2::set_pka(const uint8_t p){
    pka = p;
}

void Tag2::set_type(const uint8_t t){
    type = t;
}

void Tag2::set_hash(const uint8_t h){
    hash = h;
}

void Tag2::set_left16(const std::string & l){
    left16 = l;
}

void Tag2::set_mpi(const std::vector <mpz_class> & m){
    mpi = m;
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
        Tag2Sub2 * sub2 = new Tag2Sub2;
        sub2 -> set_time(t);
        if (i == hashed_subpackets.size()){ // not found
            hashed_subpackets.push_back(sub2);
        }
        else{                               // found
            delete hashed_subpackets[i];
            hashed_subpackets[i] = sub2;
        }
    }
}

void Tag2::set_keyid(const std::string & k){
    if (k.size() != 8){
        std::cerr << "Error: Key ID must be 8 octets." << std::endl;
        throw(1);
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
        Tag2Sub16 * sub16 = new Tag2Sub16;
        sub16 -> set_keyid(k);
        if (i == unhashed_subpackets.size()){   // not found
            unhashed_subpackets.push_back(sub16);
        }
        else{                                   // found
            delete unhashed_subpackets[i];
            unhashed_subpackets[i] = sub16;
        }
    }
}

void Tag2::set_hashed_subpackets(const std::vector <Subpacket *> & h){
    for(Subpacket *& s : hashed_subpackets){
        delete s;
    }
    hashed_subpackets.clear();
    for(Subpacket *const & s : h){
        hashed_subpackets.push_back(s -> clone());
    }
}

void Tag2::set_unhashed_subpackets(const std::vector <Subpacket *> & u){
    for(Subpacket *& s : unhashed_subpackets){
        delete s;
    }
    unhashed_subpackets.clear();
    for(Subpacket * const & s : u){
        unhashed_subpackets.push_back(s -> clone());
    }
}


Tag2 * Tag2::clone(){
    Tag2 * out = new Tag2(*this);
    out -> hashed_subpackets = get_hashed_subpackets_clone();
    out -> unhashed_subpackets = get_unhashed_subpackets_clone();
    return out;
}

Tag2 Tag2::operator=(const Tag2 & tag2){
    tag = tag2.tag;
    version = tag2.version;
    format = tag2.format;
    size = tag2.size;
    type = tag2.type;
    pka = tag2.pka;
    hash = tag2.hash;
    mpi = tag2.mpi;
    left16 = tag2.left16;
    time = tag2.time;
    keyid = tag2.keyid;
    hashed_subpackets = get_hashed_subpackets_clone();
    unhashed_subpackets = get_unhashed_subpackets_clone();
    return *this;
}

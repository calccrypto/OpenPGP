#include "Tag2.h"
Tag2::Tag2(){
    tag = 2;
}

Tag2::Tag2(std::string & data){
    tag = 2;
    read(data);
}

Tag2::~Tag2(){
    for(Subpacket *& s : hashed_subpackets){
        delete s;
    }
    for(Subpacket *& s : unhashed_subpackets){
        delete s;
    }
}

void Tag2::read(std::string & data){
    size = data.size();
    tag = 2;
    version = data[0];
    if (version < 4){
        if (data[1] != 5){
            std::cerr << "Error: Length of hashed material must be 5" << std::endl;
            exit(1);
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
        // hashed subpackets
        while (hashed.size()){
            Subpacket * temp;
            std::string subpacket_data = read_subpacket(hashed);
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
                    std::cerr << "Error: Subpacket tag not defined or reserved" << std::endl;
                    exit(1);
                    break;
            }
            temp -> read(subpacket_data);
            hashed_subpackets.push_back(temp);
        }
        // unhashed subpacketss
        uint16_t unhashed_size = toint(data.substr(0, 2), 256);
        data = data.substr(2, data.size() - 2);
        std::string unhashed = data.substr(0, unhashed_size);
        data = data.substr(unhashed_size, data.size() - unhashed_size);
        while (unhashed.size()){
            Subpacket * temp;
            std::string subpacket_data = read_subpacket(unhashed);
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
                    std::cerr << "Error: Subpacket tag not defined or reserved" << std::endl;
                    exit(1);
                    break;
            }
            temp -> read(subpacket_data);
            unhashed_subpackets.push_back(temp);
        }
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
        out << "    Signature Type: " << Signature_Types.at(type) << " (type 0x" <<  makehex(type, 2) << ")\n"
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
        out << "    RSA m**d mod n (" << mpi[0].bits() << " bits): " << mpi[0].str(16) << "\n";
    else if (pka == 17){
        out << "    DSA r (" << mpi[0].bits() << " bits): " << mpi[0].str(16) << "\n"
            << "    DSA s (" << mpi[1].bits() << " bits): " << mpi[1].str(16) << "\n";
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
    for(integer & i : mpi){
        out += write_MPI(i);
    }
    return out;
}

Tag2 * Tag2::clone(){
    Tag2 * out = new Tag2(*this);
    out -> hashed_subpackets.clear();
    out -> unhashed_subpackets.clear();
    out -> hashed_subpackets = get_hashed_subpackets_copy();
    out -> unhashed_subpackets = get_unhashed_subpackets_copy();
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

std::vector <integer> Tag2::get_mpi(){
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
    return "";
}

std::vector <Subpacket *> Tag2::get_hashed_subpackets_pointers(){
    return hashed_subpackets;
}

std::vector <Subpacket *> Tag2::get_hashed_subpackets_copy(){
    std::vector <Subpacket *> out;
    for(Subpacket *& s : hashed_subpackets){
        out.push_back(s -> clone());
    }
    return out;
}

std::vector <Subpacket *> Tag2::get_unhashed_subpackets_pointers(){
    return unhashed_subpackets;
}

std::vector <Subpacket *> Tag2::get_unhashed_subpackets_copy(){
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
    return "";
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
    for(integer & i : mpi){
        out += write_MPI(i);
    }
    return out;
}

void Tag2::set_pka(uint8_t p){
    pka = p;
}

void Tag2::set_type(uint8_t t){
    type = t;
}

void Tag2::set_hash(uint8_t h){
    hash = h;
}

void Tag2::set_left16(std::string l){
    left16 = l;
}

void Tag2::set_mpi(std::vector <integer> m){
    mpi = m;
}

void Tag2::set_time(uint32_t t){
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

void Tag2::set_keyid(std::string k){
    if (k.size() != 8){
        std::cerr << "Error: Key ID must be 8 octest" << std::endl;
        exit(1);
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

void Tag2::set_hashed_subpackets(std::vector <Subpacket *> h){
    for(Subpacket *& s : hashed_subpackets){
        delete s;
    }
    hashed_subpackets.clear();
    for(Subpacket *& s : h){
        hashed_subpackets.push_back(s -> clone());
    }
}

void Tag2::set_unhashed_subpackets(std::vector <Subpacket *> u){
    for(Subpacket *& s : unhashed_subpackets){
        delete s;
    }
    unhashed_subpackets.clear();
    for(Subpacket *& s : u){
        unhashed_subpackets.push_back(s -> clone());
    }
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

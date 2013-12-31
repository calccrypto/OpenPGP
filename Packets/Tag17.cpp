#include "Tag17.h"
Tag17::Tag17(){
    tag = 17;
}

Tag17::Tag17(std::string & data){
    tag = 17;
    read(data);
}

Tag17::~Tag17(){
    for(Subpacket *& s : attributes){
        delete s;
    }
}

void Tag17::read(std::string & data){
    size = data.size();
    while (data.size()){
        Subpacket * temp;
        std::string subpacket = read_subpacket(data);
        uint8_t type = subpacket[0];
        switch (type){
            case 1:
                temp = new Tag17Sub1;
                break;
            default:
                std::cerr << "Error: Subpacket tag not defined or reserved." << std::endl;
                throw(1);
                break;
        }
        subpacket = subpacket.substr(1, subpacket.size() - 1);
        temp -> read(subpacket);
        attributes.push_back(temp);
    }
}

std::string Tag17::show(){
    std::string out = "";
    for(unsigned int i = 0; i < attributes.size(); i++){
        out += attributes[i] -> show();
    }
    return out;
}

std::string Tag17::raw(){
    std::string out = "";
    for(Subpacket * a : attributes){
        out += a -> write();
    }
    return out;
}

// Extracts Subpacket data for figuring which subpacket type to create
// Some data is destroyed in the process
std::string Tag17::read_subpacket(std::string & data){
    size = data.size();
    uint32_t length = 0;
    uint8_t first_octet = (unsigned char) data[0];
    if (first_octet < 192){
        length = first_octet;
        data = data.substr(1, data.size() - 1);
    }
    else if ((192 <= first_octet) & (first_octet < 255)){
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

std::string Tag17::write_subpacket(uint8_t s_type, std::string data){
    if (data.size() < 192){
        return std::string(1, data.size()) + std::string(1, s_type) + data;
    }
    else if ((192 <= data.size()) && (data.size() < 8383)){
        return unhexlify(makehex(((((data.size() >> 8) + 192) << 8) + (data.size() & 0xff) - 192), 4)) + std::string(1, s_type) + data;
    }
    else{
        return "\xff" + unhexlify(makehex(data.size(), 8)) + std::string(1, s_type) + data;
    }
    return ""; // should never reach here; mainly just to remove compiler warnings
}

std::vector <Subpacket *> Tag17::get_attributes(){
    return attributes;
}

std::vector <Subpacket *> Tag17::get_attributes_clone(){
    std::vector <Subpacket *> out;
    for(Subpacket *& s : attributes){
        Subpacket * temp = s -> clone();
        out.push_back(temp);
    }
    return out;
}

void Tag17::set_attibutes(const std::vector <Subpacket *> & a){
    for(Subpacket *& s : attributes){
        delete s;
    }
    attributes.clear();
    for(Subpacket * const & s : a){
        attributes.push_back(s);
    }
}

Tag17 * Tag17::clone(){
    return new Tag17(*this);
}

#include "Tag17.h"

Tag17::Tag17():
    ID(17),
    length(),
    type(),
    attributes()
{}

Tag17::Tag17(std::string & data):
    Tag17()
{
    read(data);
}

Tag17::~Tag17(){
    attributes.clear();
}

void Tag17::read(std::string & data, const uint8_t part){
    size = data.size();
    while (data.size()){
        Tag17Subpacket::Ptr temp;
        std::string subpacket = read_subpacket(data);
        uint8_t type = subpacket[0];
        subpacket = subpacket.substr(1, subpacket.size() - 1);
        switch (type){
            case 1:
                temp = std::make_shared<Tag17Sub1>();
                break;
            default:
                throw std::runtime_error("Error: Subpacket tag not defined or reserved.");
                break;
        }
        temp -> read(subpacket);
        attributes.push_back(temp);
    }
}

std::string Tag17::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::string out = std::string(tab, ' ') + show_title();
    for(Subpacket::Ptr const & a : attributes){
        out += "\n" + a -> show(indents, indent_size);
    }
    return out;
}

std::string Tag17::raw() const{
    std::string out = "";
    for(Subpacket::Ptr const & a : attributes){
        out += a -> write();
    }
    return out;
}

// Extracts Subpacket data for figuring which subpacket type to create
// Some data is consumed in the process
std::string Tag17::read_subpacket(std::string & data){
    size = data.size();
    uint32_t length = 0;
    uint8_t first_octet = data[0];
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

std::string Tag17::write_subpacket(uint8_t s_type, std::string data) const{
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

std::vector <Tag17Subpacket::Ptr> Tag17::get_attributes() const{
    return attributes;
}

std::vector <Tag17Subpacket::Ptr> Tag17::get_attributes_clone() const{
    std::vector <Tag17Subpacket::Ptr> out;
    for(Tag17Subpacket::Ptr const & s : attributes){
        out.push_back(s -> clone());
    }
    return out;
}

void Tag17::set_attributes(const std::vector <Tag17Subpacket::Ptr> & a){
    attributes.clear();
    for(Tag17Subpacket::Ptr const & s : a){
        attributes.push_back(s -> clone());
    }
    size = raw().size();
}

Packet::Ptr Tag17::clone() const{
    return std::make_shared <Tag17> (*this);
}

#include "Tag17.h"

// Extracts Subpacket data for figuring which subpacket type to create
void Tag17::read_subpacket(const std::string & data, std::string::size_type & pos, std::string::size_type & length){
    length = 0;

    uint8_t first_octet = data[pos];
    if (first_octet < 192){
        length = first_octet;
        pos += 1;
    }
    else if ((192 <= first_octet) & (first_octet < 255)){
        length = toint(data.substr(0, 2), 256) - (192 << 8) + 192;
        pos += 2;
    }
    else if (first_octet == 255){
        length = toint(data.substr(1, 4), 256);
        pos += 5;
    }

    pos += length;
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

Tag17::Tag17()
    : ID(17),
      length(),
      type(),
      attributes()
{}

Tag17::Tag17(const std::string & data)
    : Tag17()
{
    read(data);
}

Tag17::~Tag17(){
    attributes.clear();
}

void Tag17::read(const std::string & data){
    std::string::size_type pos = 0;
    size = data.size();

    // read subpackets
    while (pos < size){
        std::string::size_type length = 0;
        read_subpacket(data, pos, length);

        Tag17Subpacket::Ptr subpacket = nullptr;
        switch (data[pos]){ // first octet of data is subpacket type
            case 1:
                subpacket = std::make_shared <Tag17Sub1> ();
                break;
            default:
                throw std::runtime_error("Error: Subpacket tag not defined or reserved.");
                break;
        }

        subpacket -> read(data.substr(pos + 1, length - 1));
        attributes.push_back(subpacket);

        // go to end of current subpacket
        pos += length;
    }
}

std::string Tag17::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string tab(indents * indent_size, ' ');
    std::string out = tab + show_title();
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

Tag17::Attributes_T Tag17::get_attributes() const{
    return attributes;
}

Tag17::Attributes_T Tag17::get_attributes_clone() const{
    std::vector <Tag17Subpacket::Ptr> out;
    for(Tag17Subpacket::Ptr const & s : attributes){
        out.push_back(s -> clone());
    }
    return out;
}

void Tag17::set_attributes(const Tag17::Attributes_T & a){
    attributes.clear();
    for(Tag17Subpacket::Ptr const & s : a){
        attributes.push_back(s -> clone());
    }
    size = raw().size();
}

Packet::Ptr Tag17::clone() const{
    return std::make_shared <Tag17> (*this);
}

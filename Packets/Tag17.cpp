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
    : User(Packet::USER_ATTRIBUTE),
      length(),
      type(),
      attributes()
{}

Tag17::Tag17(const Tag17 & copy)
    : User(copy),
      length(copy.length),
      type(copy.type),
      attributes(copy.attributes)
{
    for(Tag17Subpacket::Ptr & s : attributes){
        s = s -> clone();
    }
}

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
        if (data[pos] == Tag17Subpacket::IMAGE_ATTRIBUTE){
            subpacket = std::make_shared <Tag17Sub1> ();
        }
        else {
            throw std::runtime_error("Error: Subpacket tag not defined or reserved: " + std::to_string(data[pos]));
        }

        subpacket -> read(data.substr(pos + 1, length - 1));
        attributes.push_back(subpacket);

        // go to end of current subpacket
        pos += length;
    }
}

std::string Tag17::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    std::string out = indent + show_title();
    for(Tag17Subpacket::Ptr const & attr : attributes){
        out += "\n" + indent + tab + attr -> show(indents, indent_size);
    }
    return out;
}

std::string Tag17::raw() const{
    std::string out = "";
    for(Tag17Subpacket::Ptr const & a : attributes){
        out += a -> write();
    }
    return out;
}

Tag17::Attributes Tag17::get_attributes() const{
    return attributes;
}

Tag17::Attributes Tag17::get_attributes_clone() const{
    Attributes out;
    for(Tag17Subpacket::Ptr const & s : attributes){
        out.push_back(s -> clone());
    }
    return out;
}

void Tag17::set_attributes(const Tag17::Attributes & a){
    attributes.clear();
    for(Tag17Subpacket::Ptr const & s : a){
        attributes.push_back(s -> clone());
    }
    size = raw().size();
}

Packet::Ptr Tag17::clone() const{
    return std::make_shared <Tag17> (*this);
}

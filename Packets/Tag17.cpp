#include "Tag17.h"

namespace OpenPGP {
namespace Packet {

// Extracts Subpacket data for figuring which subpacket type to create
void Tag17::read_subpacket(const std::string & data, std::string::size_type & pos, std::string::size_type & length){
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

Tag17::Tag17()
    : User(USER_ATTRIBUTE),
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
    for(Subpacket::Tag17::Sub::Ptr & s : attributes){
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
    size = data.size();

    // read subpackets
    std::string::size_type pos = 0;
    while (pos < size){
        std::string::size_type length;
        read_subpacket(data, pos, length);

        Subpacket::Tag17::Sub::Ptr subpacket = nullptr;
        if (data[pos] == Subpacket::Tag17::IMAGE_ATTRIBUTE){
            subpacket = std::make_shared <Subpacket::Tag17::Sub1> ();
        }
        else {
            throw std::runtime_error("Error: Tag 17 Subpacket tag not defined or reserved: " + std::to_string(data[pos]));
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
    for(Subpacket::Tag17::Sub::Ptr const & attr : attributes){
        out += "\n" + indent + tab + attr -> show(indents, indent_size);
    }
    return out;
}

std::string Tag17::raw() const{
    std::string out = "";
    for(Subpacket::Tag17::Sub::Ptr const & a : attributes){
        out += a -> write();
    }
    return out;
}

Tag17::Attributes Tag17::get_attributes() const{
    return attributes;
}

Tag17::Attributes Tag17::get_attributes_clone() const{
    Attributes out;
    for(Subpacket::Tag17::Sub::Ptr const & s : attributes){
        out.push_back(s -> clone());
    }
    return out;
}

void Tag17::set_attributes(const Tag17::Attributes & a){
    attributes.clear();
    for(Subpacket::Tag17::Sub::Ptr const & s : a){
        attributes.push_back(s -> clone());
    }
    size = raw().size();
}

Tag::Ptr Tag17::clone() const{
    return std::make_shared <Packet::Tag17> (*this);
}

}
}
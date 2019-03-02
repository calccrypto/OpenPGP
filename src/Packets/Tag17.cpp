#include "Packets/Tag17.h"

namespace OpenPGP {
namespace Packet {

void Tag17::actual_read(const std::string & data){
    // read subpackets
    std::string::size_type pos = 0;
    while (pos < size){
        std::string::size_type length;
        Subpacket::Sub::read_subpacket(data, pos, length);

        Subpacket::Tag17::Sub::Ptr subpacket = nullptr;
        switch (const uint8_t type = data[pos]) {
            case Subpacket::Tag17::IMAGE_ATTRIBUTE:
                subpacket = std::make_shared <Subpacket::Tag17::Sub1> ();
                break;
            default:
                throw std::runtime_error("Error: Tag 17 Subpacket tag not defined or reserved: " + std::to_string(type));
        }

        subpacket -> read(data.substr(pos + 1, length - 1));
        attributes.push_back(subpacket);

        // go to end of current subpacket
        pos += length;
    }
}

void Tag17::show_contents(HumanReadable & hr) const{
    for(Subpacket::Tag17::Sub::Ptr const & attr : attributes){
        attr -> show(hr);
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

Tag17 & Tag17::operator=(const Tag17 & tag17) {
    User::operator=(tag17);
    length = tag17.length;
    type = tag17.type;
    attributes = tag17.attributes;

    for(Subpacket::Tag17::Sub::Ptr & s : attributes){
        s = s -> clone();
    }

    return *this;
}

}
}

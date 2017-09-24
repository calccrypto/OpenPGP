#include "Tag2Sub16.h"

Tag2Sub16::Tag2Sub16()
    : Tag2Subpacket(Tag2Subpacket::ISSUER, 8),
      keyid()
{}

Tag2Sub16::Tag2Sub16(const std::string & data)
    : Tag2Sub16()
{
    read(data);
}

void Tag2Sub16::read(const std::string & data){
    keyid = data;
}

std::string Tag2Sub16::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "Key ID: " + hexlify(keyid);
}

std::string Tag2Sub16::raw() const{
    return keyid;
}

std::string Tag2Sub16::get_keyid() const{
    return keyid;
}

void Tag2Sub16::set_keyid(const std::string & k){
    if (k.size() != 8){
        throw std::runtime_error("Error: Key ID must be 8 octets.");
    }
    keyid = k;
}

Tag2Subpacket::Ptr Tag2Sub16::clone() const{
    return std::make_shared <Tag2Sub16> (*this);
}

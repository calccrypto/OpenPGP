#include "Tag2Sub28.h"

Tag2Sub28::Tag2Sub28()
    : Tag2Subpacket(Tag2Subpacket::SIGNERS_USER_ID, 0),
      signer()
{}

Tag2Sub28::Tag2Sub28(const std::string & data)
    : Tag2Sub28()
{
    read(data);
}

void Tag2Sub28::read(const std::string & data){
    signer = data;
    size = data.size();
}

std::string Tag2Sub28::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "ID: " + signer;
}

std::string Tag2Sub28::raw() const{
    return signer;
}

std::string Tag2Sub28::get_signer() const{
    return signer;
}

void Tag2Sub28::set_signer(const std::string & s){
    size = s.size();
    signer = s;
}

Tag2Subpacket::Ptr Tag2Sub28::clone() const{
    return std::make_shared <Tag2Sub28> (*this);
}

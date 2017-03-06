#include "Tag2Sub7.h"

Tag2Sub7::Tag2Sub7()
    : Tag2Subpacket(Tag2Subpacket::ID::Revocable, 1),
      revocable()
{}

Tag2Sub7::Tag2Sub7(const std::string & data)
    : Tag2Sub7()
{
    read(data);
}

void Tag2Sub7::read(const std::string & data){
    revocable = data[0];
}

std::string Tag2Sub7::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "Revocable: " + (revocable?"True":"False");
}

std::string Tag2Sub7::raw() const{
    return (revocable?"\x01":zero);
}

bool Tag2Sub7::get_revocable() const{
    return revocable;
}

void Tag2Sub7::set_revocable(const bool r){
    revocable = r;
}

Tag2Subpacket::Ptr Tag2Sub7::clone() const{
    return std::make_shared <Tag2Sub7> (*this);
}

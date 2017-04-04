#include "Tag2Sub25.h"

Tag2Sub25::Tag2Sub25()
    : Tag2Subpacket(Tag2Subpacket::PRIMARY_USER_ID, 1),
      primary()
{}

Tag2Sub25::Tag2Sub25(const std::string & data)
    : Tag2Sub25()
{
    read(data);
}

void Tag2Sub25::read(const std::string & data){
    primary = data[0];
}

std::string Tag2Sub25::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" + 
           indent + tab + "Primary: " + + (primary?"True":"False");
}

std::string Tag2Sub25::raw() const{
    return (primary?"\x01":zero);
}

bool Tag2Sub25::get_primary() const{
    return primary;
}

void Tag2Sub25::set_primary(const bool p){
    primary = p;
}

Tag2Subpacket::Ptr Tag2Sub25::clone() const{
    return std::make_shared <Tag2Sub25> (*this);
}

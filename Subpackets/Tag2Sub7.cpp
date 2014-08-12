#include "Tag2Sub7.h"

Tag2Sub7::Tag2Sub7() :
    Tag2Subpacket(7, 1),
    revocable()
{}

Tag2Sub7::Tag2Sub7(std::string & data) :
    Tag2Sub7()
{
    read(data);
}

void Tag2Sub7::read(std::string & data){
    revocable = data[0];
}

std::string Tag2Sub7::show(const uint8_t indents, const uint8_t indent_size) const{
    return std::string(indents * indent_size, ' ') + std::string("            Revocable: ") + (revocable?"True":"False") + "\n";
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
    return Ptr(new Tag2Sub7(*this));
}

#include "Tag2Sub25.h"

Tag2Sub25::Tag2Sub25() :
    Subpacket(25, 1),
    primary()
{
}

Tag2Sub25::Tag2Sub25(std::string & data) :
    Tag2Sub25()
{
    read(data);
}

void Tag2Sub25::read(std::string & data){
    primary = data[0];
}

std::string Tag2Sub25::show() const{
    return std::string("            Primary: ") + (primary?"True":"False") + "\n";
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

Subpacket::Ptr Tag2Sub25::clone() const{
    return Ptr(new Tag2Sub25(*this));
}

#include "Tag2Sub30.h"

Tag2Sub30::Tag2Sub30() :
    Subpacket(30),
    flags()
{
}

Tag2Sub30::Tag2Sub30(std::string & data) :
    Tag2Sub30()
{
    read(data);
}

void Tag2Sub30::read(std::string & data){
    flags = data[0];
    size = data.size();
}

std::string Tag2Sub30::show() const{
    std::stringstream out;
    for(uint8_t bit = 0; bit < 8; bit++){
        if (flags & (1 << bit)){
            out << "            Flag - " << Features.at(1 << bit) << " (feat " << static_cast <unsigned int> (1 << bit) << ")\n";
        }
    }
    return out.str();
}

std::string Tag2Sub30::raw() const{
    return std::string(1, flags);
}

char Tag2Sub30::get_flags() const{
    return flags;
}

void Tag2Sub30::set_flags(const char f){
    flags = f;
}

Subpacket::Ptr Tag2Sub30::clone() const{
    return Ptr(new Tag2Sub30(*this));
}

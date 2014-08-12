#include "Tag2Sub27.h"

Tag2Sub27::Tag2Sub27() :
    Tag2Subpacket(27),
    flags()
{}

Tag2Sub27::Tag2Sub27(std::string & data) :
    Tag2Sub27()
{
    read(data);
}

void Tag2Sub27::read(std::string & data){
    flags = data[0];
    size = data.size();
}

std::string Tag2Sub27::show(const uint8_t indents, const uint8_t indent_size) const{
    uint8_t tab = indents * indent_size;
    std::stringstream out;
    for(uint8_t bit = 0; bit < 8; bit++){
        if (flags & (1 << bit)){
            out << std::string(tab, ' ') << "            Flag - " << Flags.at(1 << bit) << " (key " << static_cast <unsigned int> (1 << bit) << ")\n";
        }
    }
    return out.str();
}

std::string Tag2Sub27::raw() const{
    return std::string(1, flags);
}

char Tag2Sub27::get_flags() const{
    return flags;
}

void Tag2Sub27::set_flags(const char f){
    flags = f;
}

Tag2Subpacket::Ptr Tag2Sub27::clone() const{
    return Ptr(new Tag2Sub27(*this));
}

#include "Tag2Sub30.h"

Tag2Sub30::Tag2Sub30()
    : Tag2Subpacket(30),
      flags()
{}

Tag2Sub30::Tag2Sub30(const std::string & data)
    : Tag2Sub30()
{
    read(data);
}

void Tag2Sub30::read(const std::string & data){
    flags = data;
    size = data.size();
}

std::string Tag2Sub30::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string tab(indents * indent_size, ' ');
    std::stringstream out;
    out << tab << show_title();
    for(char const octet : flags){
        for(uint8_t bit = 0; bit < 8; bit++){
            if (octet & (1 << bit)){
                out << "\n" << tab << "            Flag - " << Features_Flags::Name.at(1 << bit) << " (feat " << std::to_string(1 << bit) << ")";
            }
        }
    }
    return out.str();
}

std::string Tag2Sub30::raw() const{
    return flags;
}

std::string Tag2Sub30::get_flags() const{
    return flags;
}

void Tag2Sub30::set_flags(const std::string & f){
    flags = f;
}

Tag2Subpacket::Ptr Tag2Sub30::clone() const{
    return std::make_shared <Tag2Sub30> (*this);
}

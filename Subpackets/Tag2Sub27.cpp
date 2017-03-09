#include "Tag2Sub27.h"

Tag2Sub27::Tag2Sub27()
    : Tag2Subpacket(Tag2Subpacket::KEY_FLAGS),
      flags()
{}

Tag2Sub27::Tag2Sub27(const std::string & data)
    : Tag2Sub27()
{
    read(data);
}

void Tag2Sub27::read(const std::string & data){
    flags = data;
    size = data.size();
}

std::string Tag2Sub27::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');

    std::string out = indent + show_title();
    for(char const octet : flags){
        for(uint8_t bit = 0; bit < 8; bit++){
            if (octet & (1 << bit)){
                out += "\n" + indent + tab + "Flag - " + Key_Flags::NAME.at(1 << bit) + " (key " + std::to_string(1 << bit) + ")";
            }
        }
    }

    return out;
}

std::string Tag2Sub27::raw() const{
    return flags;
}

std::string Tag2Sub27::get_flags() const{
    return flags;
}

void Tag2Sub27::set_flags(const std::string & f){
    flags = f;
}

Tag2Subpacket::Ptr Tag2Sub27::clone() const{
    return std::make_shared <Tag2Sub27> (*this);
}

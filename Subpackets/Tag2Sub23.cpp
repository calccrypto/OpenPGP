#include "Tag2Sub23.h"

Tag2Sub23::Tag2Sub23()
    : Tag2Subpacket(Tag2Subpacket::KEY_SERVER_PREFERENCES),
      flags()
{}

Tag2Sub23::Tag2Sub23(const std::string & data)
    : Tag2Sub23()
{
    read(data);
}

void Tag2Sub23::read(const std::string & data){
    flags = data;
    size = data.size();
}

std::string Tag2Sub23::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string tab(3 * indent_size, ' ');
    const std::string indent(indents * indent_size, ' ');

    std::string out = indent + show_title();
    for(char const octet : flags){
        for(uint8_t bit = 0; bit < 8; bit++){
            if (octet & (1 << bit)){
                out += "\n" + indent + tab + "Flag - " + Key_Server_Preferences::Name.at(1 << bit) + " (key " + std::to_string(1 << bit) + ")";
            }
        }
    }

    return out;
}

std::string Tag2Sub23::raw() const{
    return flags;
}

std::string Tag2Sub23::get_flags() const{
    return flags;
}

void Tag2Sub23::set_flags(const std::string & f){
    flags = f;
}

Tag2Subpacket::Ptr Tag2Sub23::clone() const{
    return std::make_shared <Tag2Sub23> (*this);
}

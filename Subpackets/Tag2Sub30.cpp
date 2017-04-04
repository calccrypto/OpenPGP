#include "Tag2Sub30.h"

Tag2Sub30::Tag2Sub30()
    : Tag2Subpacket(Tag2Subpacket::FEATURES),
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

std::string Tag2Sub30::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');

    std::string out = indent + show_title();
    for(char const octet : flags){
        for(uint8_t bit = 0; bit < 8; bit++){
            if (octet & (1 << bit)){
                const decltype(Features_Flags::NAME)::const_iterator ff_it = Features_Flags::NAME.find(1 << bit);
                out += "\n" + indent + tab + "Flag - " + ((ff_it == Features_Flags::NAME.end())?"Unknown":(ff_it -> second)) + " (feat " + std::to_string(1 << bit) + ")";
            }
        }
    }

    return out;
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

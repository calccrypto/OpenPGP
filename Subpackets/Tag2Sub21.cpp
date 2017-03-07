#include "Tag2Sub21.h"

Tag2Sub21::Tag2Sub21()
    : Tag2Subpacket(Tag2Subpacket::PREFERRED_HASH_ALGORITHMS),
      pha()
{}

Tag2Sub21::Tag2Sub21(const std::string & data)
    : Tag2Sub21()
{
    read(data);
}

void Tag2Sub21::read(const std::string & data){
    pha = data;
    size = data.size();
}

std::string Tag2Sub21::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');

    std::string out = indent + show_title();
    for(char const & alg : pha){
        out += "\n" + indent + tab + "hash alg - " + Hash::NAME.at(alg) + " (hash " + std::to_string(alg) + ")";
    }

    return out;
}

std::string Tag2Sub21::raw() const{
    return pha;
}

std::string Tag2Sub21::get_pha() const{
    return pha;
}

void Tag2Sub21::set_pha(const std::string & p){
    pha = p;
}

Tag2Subpacket::Ptr Tag2Sub21::clone() const{
    return std::make_shared <Tag2Sub21> (*this);
}

#include "Tag2Sub11.h"

Tag2Sub11::Tag2Sub11()
    : Tag2Subpacket(Tag2Subpacket::PREFERRED_SYMMETRIC_ALGORITHMS),
      psa()
{}

Tag2Sub11::Tag2Sub11(const std::string & data)
    : Tag2Sub11()
{
    read(data);
}

void Tag2Sub11::read(const std::string & data){
    psa = data;
    size = data.size();
}

std::string Tag2Sub11::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');

    std::string out = indent + show_title();
    for(char const & c : psa){
        out += "\n" + indent + tab + "sym alg - " + Sym::NAME.at(c) + " (sym " + std::to_string(c) + ")";
    }

    return out;
}

std::string Tag2Sub11::raw() const{
    return psa;
}

std::string Tag2Sub11::get_psa() const{
    return psa;
}

void Tag2Sub11::set_psa(const std::string & s){
    psa = s;
}

Tag2Subpacket::Ptr Tag2Sub11::clone() const{
    return std::make_shared <Tag2Sub11> (*this);
}

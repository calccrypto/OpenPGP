#include "Tag2Sub11.h"

Tag2Sub11::Tag2Sub11():
    Tag2Subpacket(11),
    psa()
{}

Tag2Sub11::Tag2Sub11(std::string & data):
    Tag2Sub11()
{
    read(data);
}

void Tag2Sub11::read(std::string & data){
    psa = data;
    size = data.size();
}

std::string Tag2Sub11::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::stringstream out;
    out << std::string(tab, ' ') << show_title();
    for(char const & c : psa){
        out << "\n" << std::string(tab, ' ') << "            sym alg - " << Symmetric_Algorithms.at(c) << " (sym " << static_cast <unsigned int> (c) << ")";
    }
    return out.str();
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

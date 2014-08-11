#include "Tag2Sub11.h"

Tag2Sub11::Tag2Sub11() :
    Subpacket(11),
    psa()
{
}

Tag2Sub11::Tag2Sub11(std::string & data) :
    Tag2Sub11()
{
    read(data);
}

void Tag2Sub11::read(std::string & data){
    psa = data;
    size = data.size();
}

std::string Tag2Sub11::show(const uint8_t indent) const{
    std::stringstream out;
    for(unsigned int x = 0; x < psa.size(); x++){
        out << std::string(indent, ' ') << "            sym alg - " << Symmetric_Algorithms.at(psa[x]) << " (sym " << static_cast <unsigned int> (psa[x]) << ")\n";
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

Subpacket::Ptr Tag2Sub11::clone() const{
    return Ptr(new Tag2Sub11(*this));
}

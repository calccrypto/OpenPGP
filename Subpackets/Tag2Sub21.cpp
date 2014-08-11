#include "Tag2Sub21.h"

Tag2Sub21::Tag2Sub21() :
    Subpacket(21),
    pha()
{}

Tag2Sub21::Tag2Sub21(std::string & data) :
    Tag2Sub21()
{
    read(data);
}

void Tag2Sub21::read(std::string & data){
    pha = data;
    size = data.size();
}

std::string Tag2Sub21::show(const uint8_t indents, const uint8_t indent_size) const{
    uint8_t tab = indents * indent_size;
    std::stringstream out;
    for(unsigned int x = 0; x < pha.size(); x++){
        out << std::string(tab, ' ') << "            hash alg - " << Hash_Algorithms.at(pha[x]) << " (hash " << static_cast <unsigned int> (pha[x]) << ")\n";
    }
    return out.str();
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

Subpacket::Ptr Tag2Sub21::clone() const{
    return Ptr(new Tag2Sub21(*this));
}

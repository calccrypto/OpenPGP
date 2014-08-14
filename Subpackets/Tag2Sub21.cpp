#include "Tag2Sub21.h"

Tag2Sub21::Tag2Sub21():
    Tag2Subpacket(21),
    pha()
{}

Tag2Sub21::Tag2Sub21(std::string & data):
    Tag2Sub21()
{
    read(data);
}

void Tag2Sub21::read(std::string & data){
    pha = data;
    size = data.size();
}

std::string Tag2Sub21::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::stringstream out;
    out << std::string(tab, ' ') << show_title();
    for(unsigned int x = 0; x < pha.size(); x++){
        out << "\n" << std::string(tab, ' ') << "            hash alg - " << Hash_Algorithms.at(pha[x]) << " (hash " << static_cast <unsigned int> (pha[x]) << ")";
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

Tag2Subpacket::Ptr Tag2Sub21::clone() const{
    return std::make_shared <Tag2Sub21> (*this);
}

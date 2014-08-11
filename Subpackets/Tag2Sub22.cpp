#include "Tag2Sub22.h"

Tag2Sub22::Tag2Sub22() :
    Subpacket(22),
    pca()
{
}

Tag2Sub22::Tag2Sub22(std::string & data) :
    Tag2Sub22()
{
    read(data);
}

void Tag2Sub22::read(std::string & data){
    pca = data;
    size = data.size();
}

std::string Tag2Sub22::show(const uint8_t indent) const{
    std::stringstream out;
    for(unsigned int x = 0; x < pca.size(); x++){
        out << std::string(indent, ' ') << "            comp alg - " << Compression_Algorithms.at(pca[x]) << " (comp " << static_cast <unsigned int> (pca[x]) << ")\n";
    }
    return out.str();
}

std::string Tag2Sub22::raw() const{
    return pca;
}

std::string Tag2Sub22::get_pca() const{
    return pca;
}

void Tag2Sub22::set_pca(const std::string & c){
    pca = c;
}

Subpacket::Ptr Tag2Sub22::clone() const{
    return Ptr(new Tag2Sub22(*this));
}

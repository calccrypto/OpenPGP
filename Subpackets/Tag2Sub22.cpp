#include "Tag2Sub22.h"

Tag2Sub22::Tag2Sub22():
    Tag2Subpacket(22),
    pca()
{}

Tag2Sub22::Tag2Sub22(std::string & data):
    Tag2Sub22()
{
    read(data);
}

void Tag2Sub22::read(std::string & data){
    pca = data;
    size = data.size();
}

std::string Tag2Sub22::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::stringstream out;
    out << std::string(tab, ' ') << show_title();
    for(unsigned int x = 0; x < pca.size(); x++){
        out << "\n" << std::string(tab, ' ') << "            comp alg - " << Compression_Algorithms.at(pca[x]) << " (comp " << static_cast <unsigned int> (pca[x]) << ")";
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

Tag2Subpacket::Ptr Tag2Sub22::clone() const{
    return std::make_shared <Tag2Sub22> (*this);
}

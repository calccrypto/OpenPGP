#include "Tag2Sub31.h"

Tag2Sub31::Tag2Sub31():
    Tag2Subpacket(31),
    pka(), ha(),
    hash()
{}

Tag2Sub31::Tag2Sub31(std::string & data):
    Tag2Sub31()
{
    read(data);
}

void Tag2Sub31::read(std::string & data){
    pka = data[0];
    ha = data[1];
    hash = data.substr(2, data.size() - 2);
    size = data.size();
}

std::string Tag2Sub31::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::stringstream out;
    out << std::string(tab, ' ') << show_title() << "\n"
        << std::string(tab, ' ') << "            Public Key Algorithm: " << Public_Key_Algorithms.at(pka) << " (pka " << static_cast <unsigned int> (pka) << ")\n"
        << std::string(tab, ' ') << "            Hash Algorithm: " << Hash_Algorithms.at(ha) << " (hash " << static_cast <unsigned int> (ha) << ")\n"
        << std::string(tab, ' ') << "            Hash: " << hexlify(hash);
    return out.str();
}

std::string Tag2Sub31::raw() const{
    return std::string(1, pka) + std::string(1, ha) + hash;
}

uint8_t Tag2Sub31::get_pka() const{
    return pka;
}

uint8_t Tag2Sub31::get_ha() const{
    return ha;
}

std::string Tag2Sub31::get_hash() const{
    return hash;
}

void Tag2Sub31::set_pka(const uint8_t p){
    pka = p;
}

void Tag2Sub31::set_ha(const uint8_t h){
    ha = h;
}

void Tag2Sub31::set_hash(const std::string & h){
    hash = h;
}

Tag2Subpacket::Ptr Tag2Sub31::clone() const{
    return std::make_shared <Tag2Sub31> (*this);
}

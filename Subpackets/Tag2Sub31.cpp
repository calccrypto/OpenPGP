#include "Tag2Sub31.h"

Tag2Sub31::Tag2Sub31() :
    Subpacket(31),
    pka(), ha(),
    hash()
{
}

Tag2Sub31::Tag2Sub31(std::string & data) :
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

std::string Tag2Sub31::show(){
    std::stringstream out;
    out << "            Public Key Algorithm: " << Public_Key_Algorithms.at(pka) << " (pka " << (unsigned int) pka << ")\n"
        << "            Hash Algorithm: " << Hash_Algorithms.at(ha) << " (hash " << (unsigned int) ha << ")\n"
        << "            Hash: " << hexlify(hash);
    return out.str();
}

std::string Tag2Sub31::raw(){
    return std::string(1, pka) + std::string(1, ha) + hash;
}

uint8_t Tag2Sub31::get_pka(){
    return pka;
}

uint8_t Tag2Sub31::get_ha(){
    return ha;
}

std::string Tag2Sub31::get_hash(){
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

Subpacket::Ptr Tag2Sub31::clone() const{
    return Ptr(new Tag2Sub31(*this));
}

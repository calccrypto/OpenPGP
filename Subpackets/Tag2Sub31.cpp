#include "Tag2Sub31.h"

Tag2Sub31::Tag2Sub31()
    : Tag2Subpacket(31),
      pka(), hash_alg(),
      hash()
{}

Tag2Sub31::Tag2Sub31(const std::string & data)
    : Tag2Sub31()
{
    read(data);
}

void Tag2Sub31::read(const std::string & data){
    pka = data[0];
    hash_alg = data[1];
    hash = data.substr(2, data.size() - 2);
    size = data.size();
}

std::string Tag2Sub31::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string tab(indents * indent_size, ' ');
    std::stringstream out;
    out << tab << show_title() << "\n"
        << tab << "            Public Key Algorithm: " << PKA::Name.at(pka) << " (pka " << std::to_string(pka) << ")\n"
        << tab << "            Hash Algorithm: " << Hash::Name.at(hash_alg) << " (hash " << std::to_string(hash_alg) << ")\n"
        << tab << "            Hash: " << hexlify(hash);
    return out.str();
}

std::string Tag2Sub31::raw() const{
    return std::string(1, pka) + std::string(1, hash_alg) + hash;
}

uint8_t Tag2Sub31::get_pka() const{
    return pka;
}

uint8_t Tag2Sub31::get_hash_alg() const{
    return hash_alg;
}

std::string Tag2Sub31::get_hash() const{
    return hash;
}

void Tag2Sub31::set_pka(const uint8_t p){
    pka = p;
}

void Tag2Sub31::set_hash_alg(const uint8_t h){
    hash_alg = h;
}

void Tag2Sub31::set_hash(const std::string & h){
    hash = h;
}

Tag2Subpacket::Ptr Tag2Sub31::clone() const{
    return std::make_shared <Tag2Sub31> (*this);
}

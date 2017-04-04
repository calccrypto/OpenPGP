#include "Tag2Sub31.h"

Tag2Sub31::Tag2Sub31()
    : Tag2Subpacket(Tag2Subpacket::SIGNATURE_TARGET),
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

std::string Tag2Sub31::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    const decltype(PKA::NAME)::const_iterator pka_it = PKA::NAME.find(pka);
    const decltype(Hash::NAME)::const_iterator hash_it = Hash::NAME.find(hash_alg);
    return indent + show_title() + "\n" +
           indent + tab + "Public Key Algorithm: " + ((pka_it == PKA::NAME.end())?"Unknown":(pka_it -> second)) + " (pka " + std::to_string(pka) + ")\n" +
           indent + tab + "Hash Algorithm: " + ((hash_it == Hash::NAME.end())?"Unknown":(hash_it -> second)) + " (hash " + std::to_string(hash_alg) + ")\n" +
           indent + tab + "Hash: " + hexlify(hash);
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

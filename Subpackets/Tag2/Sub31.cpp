#include "Sub31.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub31::Sub31()
    : Sub(SIGNATURE_TARGET),
      pka(), hash_alg(),
      hash()
{}

Sub31::Sub31(const std::string & data)
    : Sub31()
{
    read(data);
}

void Sub31::read(const std::string & data){
    if (data.size()){
        pka = data[0];
        hash_alg = data[1];
        hash = data.substr(2, data.size() - 2);
        size = data.size();
    }
}

std::string Sub31::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    const decltype(PKA::NAME)::const_iterator pka_it = PKA::NAME.find(pka);
    const decltype(Hash::NAME)::const_iterator hash_it = Hash::NAME.find(hash_alg);
    return indent + show_title() + "\n" +
           indent + tab + "Public Key Algorithm: " + ((pka_it == PKA::NAME.end())?"Unknown":(pka_it -> second)) + " (pka " + std::to_string(pka) + ")\n" +
           indent + tab + "Hash Algorithm: " + ((hash_it == Hash::NAME.end())?"Unknown":(hash_it -> second)) + " (hash " + std::to_string(hash_alg) + ")\n" +
           indent + tab + "Hash: " + hexlify(hash);
}

std::string Sub31::raw() const{
    return std::string(1, pka) + std::string(1, hash_alg) + hash;
}

uint8_t Sub31::get_pka() const{
    return pka;
}

uint8_t Sub31::get_hash_alg() const{
    return hash_alg;
}

std::string Sub31::get_hash() const{
    return hash;
}

void Sub31::set_pka(const uint8_t p){
    pka = p;
}

void Sub31::set_hash_alg(const uint8_t h){
    hash_alg = h;
}

void Sub31::set_hash(const std::string & h){
    hash = h;
}

Sub::Ptr Sub31::clone() const{
    return std::make_shared <Sub31> (*this);
}

}
}
}
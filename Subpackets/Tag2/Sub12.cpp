#include "Sub12.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub12::Sub12()
    : Sub(REVOCATION_KEY),
      _class(),
      pka(),
      fingerprint()
{}

Sub12::Sub12(const std::string & data)
    : Sub12()
{
    read(data);
}

void Sub12::read(const std::string & data){
    if (data.size()){
        _class = data[0];
        pka = data[1];
        fingerprint = data.substr(2, 20);
        size = data.size();
    }
}

std::string Sub12::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    const decltype(PKA::NAME)::const_iterator pka_it = PKA::NAME.find(pka);
    return indent + show_title() + "\n" +
           indent + tab + "Class: " + std::to_string(_class) + "\n" +
           indent + tab + "Public Key Algorithm: " + ((pka_it == PKA::NAME.end())?"Unknown":(pka_it -> second)) + " (pka " + std::to_string(pka) + ")\n" +
           indent + tab + "Fingerprint: " + fingerprint;
}

std::string Sub12::raw() const{
    return std::string(1, _class) + std::string(1, pka) + fingerprint;
}

uint8_t Sub12::get_class() const{
    return _class;
}

uint8_t Sub12::get_pka() const{
    return pka;
}

std::string Sub12::get_fingerprint() const{
    return fingerprint;
}

void Sub12::set_class(const uint8_t c){
    _class = c;
}

void Sub12::set_pka(const uint8_t p){
    pka = p;
}

void Sub12::set_fingerprint(const std::string & f){
    fingerprint = f;
}

Sub::Ptr Sub12::clone() const{
    return std::make_shared <Sub12> (*this);
}

}
}
}
#include "Tag2Sub12.h"

Tag2Sub12::Tag2Sub12()
    : Tag2Subpacket(Tag2Subpacket::REVOCATION_KEY),
      _class(),
      pka(),
      fingerprint()
{}

Tag2Sub12::Tag2Sub12(const std::string & data)
    : Tag2Sub12()
{
    read(data);
}

void Tag2Sub12::read(const std::string & data){
    _class = data[0];
    pka = data[1];
    fingerprint = data.substr(2, 20);
    size = data.size();
}

std::string Tag2Sub12::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    const decltype(PKA::NAME)::const_iterator pka_it = PKA::NAME.find(pka);
    return indent + show_title() + "\n" +
           indent + tab + "Class: " + std::to_string(_class) + "\n" +
           indent + tab + "Public Key Algorithm: " + ((pka_it == PKA::NAME.end())?"Unknown":(pka_it -> second)) + " (pka " + std::to_string(pka) + ")\n" +
           indent + tab + "Fingerprint: " + fingerprint;
}

std::string Tag2Sub12::raw() const{
    return std::string(1, _class) + std::string(1, pka) + unhexlify(fingerprint);
}

uint8_t Tag2Sub12::get_class() const{
    return _class;
}

uint8_t Tag2Sub12::get_pka() const{
    return pka;
}

std::string Tag2Sub12::get_fingerprint() const{
    return fingerprint;
}

void Tag2Sub12::set_class(const uint8_t c){
    _class = c;
}

void Tag2Sub12::set_pka(const uint8_t p){
    pka = p;
}

void Tag2Sub12::set_fingerprint(const std::string & f){
    fingerprint = f;
}

Tag2Subpacket::Ptr Tag2Sub12::clone() const{
    return std::make_shared <Tag2Sub12> (*this);
}

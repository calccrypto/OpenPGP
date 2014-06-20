#include "Tag2Sub12.h"

Tag2Sub12::Tag2Sub12() :
    Subpacket(12),
    _class(),
    pka(),
    fingerprint()
{
}

Tag2Sub12::Tag2Sub12(std::string & data) :
    Tag2Sub12()
{
    read(data);
}

void Tag2Sub12::read(std::string & data){
    _class = data[0];
    pka = data[1];
    fingerprint = data.substr(2, 20);
    size = data.size();
}

std::string Tag2Sub12::show(){
    std::stringstream out;
    out << "            Class: " << (unsigned int) _class << "\n"
        << "            Public Key Algorithm: " << Public_Key_Algorithms.at(pka) << " (pka " << (unsigned int) pka << ")\n"
        << "            Fingerprint: " << fingerprint << "\n";
    return out.str();
}

std::string Tag2Sub12::raw(){
    return std::string(1, _class) + std::string(1, pka) + unhexlify(fingerprint);
}

uint8_t Tag2Sub12::get_class(){
    return _class;
}

uint8_t Tag2Sub12::get_pka(){
    return pka;
}

std::string Tag2Sub12::get_fingerprint(){
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

Subpacket::Ptr Tag2Sub12::clone() const{
    return Ptr(new Tag2Sub12(*this));
}

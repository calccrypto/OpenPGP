#include "Tag4.h"

Tag4::Tag4() :
    Packet(4, 3),
    type(), hash(), pka(),
    keyid(),
    nested()
{
}

Tag4::Tag4(std::string & data) :
    Tag4()
{
    read(data);
}

void Tag4::read(std::string & data){
    size = data.size();
    version = data[0];                  // 3
    type = data[1];
    hash = data[2];
    pka = data[3];
    keyid = data.substr(4, 8);
    nested = data[12];
    data = data.substr(12, data.size() - 12);
}

std::string Tag4::show() const{
    std::stringstream out;
    out << "    Version: " << static_cast <unsigned int> (version) << "\n"
        << "    Signature Type: " << Signature_Types.at(type) << " (sig " << static_cast <unsigned int> (type) << ")\n"
        << "    Hash Algorithm: " << Hash_Algorithms.at(hash) << " (hash " << static_cast <unsigned int> (hash) << ")\n"
        << "    Public Key Algorithm: " << Public_Key_Algorithms.at(pka) << " (pka " << static_cast <unsigned int> (pka) << ")\n"
        << "    KeyID: " << keyid << "\n"
        << "    Nested: " << static_cast <bool> (nested) << "\n";
    return out.str();
}

std::string Tag4::raw() const{
    return "\x03" + std::string(1, type) + std::string(1, hash) + std::string(1, pka) + keyid + std::string(1, nested);
}

uint8_t Tag4::get_type() const{
    return type;
}

uint8_t Tag4::get_hash() const{
    return hash;
}

uint8_t Tag4::get_pka() const{
    return pka;
}

std::string Tag4::get_keyid() const{
    return keyid;
}

uint8_t Tag4::get_nested() const{
    return nested;
}

void Tag4::set_type(const uint8_t t){
    type = t;
    size = raw().size();
}

void Tag4::set_hash(const uint8_t h){
    hash = h;
    size = raw().size();
}

void Tag4::set_pka(const uint8_t p){
    pka = p;
    size = raw().size();
}

void Tag4::set_keyid(const std::string & k){
    if (k.size() != 8){
        throw std::runtime_error("Error: Key ID must be 8 octets.");
    }
    keyid = k;
    size = raw().size();
}

void Tag4::set_nested(const uint8_t n){
    nested = n;
    size = raw().size();
}

Packet::Ptr Tag4::clone() const{
    return Ptr(new Tag4(*this));
}

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

// need to indent for nested
std::string Tag4::show(){
    std::stringstream out;
    out << "Version: " << (unsigned int) version << "\n"
        << "Signature Type: " << Signature_Types.at(type) << " (sig " << (unsigned int) type << ")\n"
        << "Hash Algorithm: " << Hash_Algorithms.at(hash) << " (hash " << (unsigned int) hash << ")\n"
        << "Public Key Algorithm: " << Public_Key_Algorithms.at(pka) << " (pka " << (unsigned int) pka << ")\n"
        << "KeyID: " << keyid << "\n"
        << "Nested: " << (bool) nested << "\n";
    return out.str();
}

std::string Tag4::raw(){
    std::cerr << "Warning: Function not completed" << std::endl;;
    std::string out = "\x03" + std::string(1, type) + std::string(1, hash) + std::string(1, pka) + keyid + std::string(1, nested);
    // need to add nested packet
    return out;
}

uint8_t Tag4::get_type(){
    return type;
}

uint8_t Tag4::get_hash(){
    return hash;
}

uint8_t Tag4::get_pka(){
    return pka;
}

std::string Tag4::get_keyid(){
    return keyid;
}

uint8_t Tag4::get_nested(){
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

#include "s2k.h"

// RFC 4880 sec 3.7.1.3
uint32_t coded_count(unsigned int c){
    return (16 + (c & 15)) << ((c >> 4) + EXPBIAS);
}

std::string S2K::show_title() const{
    std::stringstream out;
    out << "    " << String2Key_Specifiers.at(type) << " (s2k " << static_cast <unsigned int> (type) << "):";
    return out.str();
}

S2K::S2K(uint8_t type):
    type(type),
    hash()
{}

S2K::~S2K(){}

std::string S2K::write() const{
    return raw();
}

uint8_t S2K::get_type() const{
    return type;
}

uint8_t S2K::get_hash() const{
    return hash;
}

void S2K::set_type(const uint8_t t){
    type = t;
}

void S2K::set_hash(const uint8_t h){
    hash = h;
}

S2K0::S2K0(uint8_t type):
    S2K(type)
{}

S2K0::S2K0():
    S2K0(0)
{}

S2K0::~S2K0(){}

void S2K0::read(std::string & data, const uint8_t part){
    type = data[0];
    hash = data[2];
    data = data.substr(2, data.size() - 2);
}

std::string S2K0::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::stringstream out;
    out << std::string(tab, ' ') << show_title() << "\n"
        << std::string(tab, ' ') << "        Hash: " << Hash_Algorithms.at(hash) << " (hash " << static_cast <unsigned int> (hash) << ")";
    return out.str();
}

std::string S2K0::raw() const{
    return "\x00" + std::string(1, hash);
}

std::string S2K0::run(const std::string & pass, unsigned int sym_key_len) const{
    std::string out = "";
    unsigned int counter = 0;
    while (out.size() < sym_key_len){
        out += use_hash(hash, std::string(counter++, 0) + pass);
    }
    return out.substr(0, sym_key_len);
}

S2K::Ptr S2K0::clone() const{
    return std::make_shared <S2K0> (*this);
}

S2K1::S2K1(uint8_t type):
    S2K0(type),
    salt()
{}

S2K1::S2K1():
    S2K1(1)
{}

S2K1::~S2K1(){}

void S2K1::read(std::string & data, const uint8_t part){
    type = data[0];
    hash = data[1];
    salt = data.substr(2, 8);
    data = data.substr(10, data.size() - 10);
}

std::string S2K1::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::stringstream out;
    out << std::string(tab, ' ') << show_title() << "\n"
        << std::string(tab, ' ') << "        Hash: " << Hash_Algorithms.at(hash) << " (hash " << static_cast <unsigned int> (hash) << ")\n"
        << std::string(tab, ' ') << "        Salt: " << hexlify(salt);
    return out.str();
}

std::string S2K1::raw() const{
    return "\x01" + std::string(1, hash) + salt;
}

std::string S2K1::run(const std::string & pass, unsigned int sym_key_len) const{
    std::string out = "";
    unsigned int counter = 0;
    while (out.size() < sym_key_len){
        out += use_hash(hash, std::string(counter++, 0) + salt + pass);
    }
    return out.substr(0, sym_key_len);
}

std::string S2K1::get_salt() const{
    return salt;
}

void S2K1::set_salt(const std::string & s){
    salt = s;
}

S2K::Ptr S2K1::clone() const{
    return std::make_shared <S2K1> (*this);
}

S2K3::S2K3():
    S2K1(3),
    count()
{}

S2K3::~S2K3(){}

void S2K3::read(std::string & data, const uint8_t part){
    type = data[0];
    hash = data[1];
    salt = data.substr(2, 8);
    count = data[10];
    data = data.substr(11, data.size() - 11);
}

std::string S2K3::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::stringstream out;
    out << std::string(tab, ' ') << show_title() << "\n"
        << std::string(tab, ' ') << "        Hash: " << Hash_Algorithms.at(hash) << " (hash " << static_cast <unsigned int> (hash) << ")\n"
        << std::string(tab, ' ') << "        Salt: " << hexlify(salt) << "\n"
        << std::string(tab, ' ') << "        Coded Count: " << coded_count(count) << " (count " << static_cast <unsigned int> (count) << ")";
    return out.str();
}

std::string S2K3::raw() const{
    return "\x03" + std::string(1, hash) + salt + unhexlify(makehex(count, 2));
}

std::string S2K3::run(const std::string & pass, unsigned int sym_key_len) const{
    // get string to hash
    std::string to_hash = "";
    while (to_hash.size() < coded_count(count)){// coded count is count of octets, not iterations
        to_hash += salt + pass;
    }
    to_hash = to_hash.substr(0, coded_count(count));
    // hash string
    std::string out = "";
    unsigned int context = 0;
    while (out.size() < sym_key_len){
        out += use_hash(hash, std::string(context++, 0) + to_hash);
    }
    return out.substr(0, sym_key_len);
}

uint8_t S2K3::get_count() const{
    return count;
}

void S2K3::set_count(const uint8_t c){
    count = c;
}

S2K::Ptr S2K3::clone() const{
    return std::make_shared <S2K3> (*this);
}

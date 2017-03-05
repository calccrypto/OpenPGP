#include "s2k.h"

const uint8_t S2K::ID::Simple_S2K              = 0;
const uint8_t S2K::ID::Salted_S2K              = 1;
const uint8_t S2K::ID::Iterated_and_Salted_S2K = 3;

const std::map <uint8_t, std::string> S2K::Name = {
            std::make_pair(ID::Simple_S2K,              "Simple S2K"),
            std::make_pair(ID::Salted_S2K,              "Salted S2K"),
            std::make_pair(2,                           "Reserved value"),
            std::make_pair(ID::Iterated_and_Salted_S2K, "Iterated and Salted S2K"),
            std::make_pair(100,                         "Private/Experimental S2K"),
            std::make_pair(101,                         "Private/Experimental S2K"),
            std::make_pair(102,                         "Private/Experimental S2K"),
            std::make_pair(103,                         "Private/Experimental S2K"),
            std::make_pair(104,                         "Private/Experimental S2K"),
            std::make_pair(105,                         "Private/Experimental S2K"),
            std::make_pair(106,                         "Private/Experimental S2K"),
            std::make_pair(107,                         "Private/Experimental S2K"),
            std::make_pair(108,                         "Private/Experimental S2K"),
            std::make_pair(109,                         "Private/Experimental S2K"),
            std::make_pair(110,                         "Private/Experimental S2K"),
};

std::string S2K::show_title() const{
    return "    " + S2K::Name.at(type) + " (s2k " + std::to_string(type) + "):";
}

S2K::S2K(uint8_t t)
    : type(t),
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

S2K0::S2K0(uint8_t t)
    : S2K(t)
{}

S2K0::S2K0()
    : S2K0(0)
{}

S2K0::~S2K0(){}

void S2K0::read(const std::string & data, std::string::size_type & pos){
    type = data[pos];
    hash = data[pos + 1];
    pos += 2;
}

std::string S2K0::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string tab(indents * indent_size, ' ');
    std::stringstream out;
    out << tab << show_title() << "\n"
        << tab << "        Hash: " << Hash::Name.at(hash) << " (hash " << std::to_string(hash) << ")";
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

S2K1::S2K1(uint8_t t)
    : S2K0(t),
      salt()
{}

S2K1::S2K1()
    : S2K1(1)
{}

S2K1::~S2K1(){}

void S2K1::read(const std::string & data, std::string::size_type & pos){
    type = data[pos];
    hash = data[pos + 1];
    salt = data.substr(pos + 2, 8);
    pos += 10;
}

std::string S2K1::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string tab(indents * indent_size, ' ');
    std::stringstream out;
    out << tab << show_title() << "\n"
        << tab << "        Hash: " << Hash::Name.at(hash) << " (hash " << std::to_string(hash) << ")"
        << tab << "        Salt: " << hexlify(salt);
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

uint32_t S2K3::coded_count(const uint8_t c){
    return (16 + (c & 15)) << ((c >> 4) + S2K3::EXPBIAS);
}

S2K3::S2K3()
    : S2K1(3),
      count()
{}

S2K3::~S2K3(){}

void S2K3::read(const std::string & data, std::string::size_type & pos){
    type  = data[pos];
    hash  = data[pos + 1];
    salt  = data.substr(pos + 2, 8);
    count = data[pos + 10];
    pos += 11;
}

std::string S2K3::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string tab(indents * indent_size, ' ');
    std::stringstream out;
    out << tab << show_title() << "\n"
        << tab << "        Hash: " << Hash::Name.at(hash) << " (hash " << std::to_string(hash) << ")"
        << tab << "        Salt: " << hexlify(salt) << "\n"
        << tab << "        Coded Count: " << S2K3::coded_count(count) << " (count " << std::to_string(count) << ")";
    return out.str();
}

std::string S2K3::raw() const{
    return "\x03" + std::string(1, hash) + salt + unhexlify(makehex(count, 2));
}

std::string S2K3::run(const std::string & pass, unsigned int sym_key_len) const{
    // get string to hash
    std::string to_hash = "";
    while (to_hash.size() < S2K3::coded_count(count)){// coded count is count of octets, not iterations
        to_hash += salt + pass;
    }
    to_hash = to_hash.substr(0, S2K3::coded_count(count));
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

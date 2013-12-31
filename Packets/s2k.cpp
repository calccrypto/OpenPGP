#include "s2k.h"

// RFC 4880 sec 3.7.1.3
uint32_t coded_count(unsigned int c){
    return (16 + (c & 15)) << ((c >> 4) + EXPBIAS);
}

S2K::~S2K(){}

std::string S2K::write(){
    return raw();
}

uint8_t S2K::get_type(){
    return type;
}

uint8_t S2K::get_hash(){
    return hash;
}

void S2K::set_type(const uint8_t t){
    type = t;
}

void S2K::set_hash(const uint8_t h){
    hash = h;
}

S2K0::S2K0(){
    type = 0;
}

S2K0::~S2K0(){}

void S2K0::read(std::string & data){
    type = data[0];
    hash = data[2];
    data = data.substr(2, data.size() - 2);
}

std::string S2K0::show(){
    std::stringstream out;
    out << "        Hash: " << Hash_Algorithms.at(hash) << " (hash " << (int) hash << ")\n";
    return out.str();
}

std::string S2K0::raw(){
    return "\x00" + std::string(1, hash);
}

std::string S2K0::run(std::string pass, unsigned int sym_len){
    std::string out = "";
    unsigned int counter = 0;
    while (out.size() < sym_len){
        out += use_hash(hash, std::string(counter++, 0) + pass);
    }
    return out.substr(0, sym_len);
}

S2K0 * S2K0::clone(){
    return new S2K0(*this);
}

S2K1::S2K1(){
    type = 1;
}

S2K1::~S2K1(){}

void S2K1::read(std::string & data){
    type = data[0];
    hash = data[1];
    salt = data.substr(2, 8);
    data = data.substr(10, data.size() - 10);
}

std::string S2K1::show(){
    std::stringstream out;
    out << "        Hash: " << Hash_Algorithms.at(hash) << " (hash " << (int) hash << ")\n"
        << "        Salt: " << hexlify(salt) << "\n";
    return out.str();
}

std::string S2K1::raw(){
    return "\x01" + std::string(1, hash) + salt;
}

std::string S2K1::run(std::string pass, unsigned int sym_len){
    std::string out = "";
    unsigned int counter = 0;
    while (out.size() < sym_len){
        out += use_hash(hash, std::string(counter++, 0) + salt + pass);
    }
    return out.substr(0, sym_len);
}


std::string S2K1::get_salt(){
    return salt;
}

void S2K1::set_salt(const std::string & s){
    salt = s;
}

S2K1 * S2K1::clone(){
    return new S2K1(*this);
}

S2K3::S2K3(){
    type = 3;
}

S2K3::~S2K3(){}

void S2K3::read(std::string & data){
    type = data[0];
    hash = data[1];
    salt = data.substr(2, 8);
    count = data[10];
    data = data.substr(11, data.size() - 11);
}

std::string S2K3::show(){
    std::stringstream out;
    out << "        Hash: " << Hash_Algorithms.at(hash) << " (hash " << (int) hash << ")\n"
        << "        Salt: " << hexlify(salt) << "\n"
        << "        Coded Count: " << coded_count(count) << " (count " << (int) count << ")\n";
    return out.str();
}

std::string S2K3::raw(){
    return "\x03" + std::string(1, hash) + salt + unhexlify(makehex(count, 2));
}

std::string S2K3::run(std::string pass, unsigned int sym_len){
    // get string to hash
    std::string to_hash = "";
    while (to_hash.size() < coded_count(count)){// coded count is count of octets, not iterations
        to_hash += salt + pass;
    }
    to_hash = to_hash.substr(0, coded_count(count));
    // hash string
    std::string out = "";
    unsigned int context = 0;
    while (out.size() < sym_len){
        out += use_hash(hash, std::string(context++, 0) + to_hash);
    }
    return out.substr(0, sym_len);
}

uint8_t S2K3::get_count(){
    return count;
}

void S2K3::set_count(const uint8_t c){
    count = c;
}

S2K3 * S2K3::clone(){
    return new S2K3(*this);
}

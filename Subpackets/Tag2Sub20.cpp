#include "Tag2Sub20.h"
Tag2Sub20::Tag2Sub20(){
    type = 20;
}

Tag2Sub20::Tag2Sub20(std::string & data){
    type = 20;
    read(data);
}

void Tag2Sub20::read(std::string & data){
    flags = data.substr(0, 4);
    mlen = toint(data.substr(4, 2), 256);
    nlen  = toint(data.substr(6, 2), 256);
    data = data.substr(8, data.size() - 8);
    m = data.substr(0, mlen);
    data = data.substr(mlen, data.size() - mlen);
    n = data.substr(0, nlen);
    size = mlen + nlen + 4;
}

std::string Tag2Sub20::show(){
    std::stringstream out;
    for(unsigned int x = 0; x < 4; x++){
        out << "            Flag - " << Notation.at(flags[x]) << " (not " << (unsigned int) flags[x] << ")\n";
    }
    out << "\n"
        << "            Name: " << m << "\n"
        << "            Value: " << n << "\n";
    return out.str();
}
std::string Tag2Sub20::raw(){
    return flags + unhexlify(makehex(m.size(), 4)) + unhexlify(makehex(n.size(), 4)) + m + n;
}

std::string Tag2Sub20::get_flags(){
    return flags;
}

std::string Tag2Sub20::get_m(){
    return m;
}

std::string Tag2Sub20::get_n(){
    return n;
}

void Tag2Sub20::set_flags(const std::string & f){
    if (f.size() != 4){
        std::cerr << "Error: 4 flag octets required." << std::endl;
        exit(1);
    }
    flags = f;
}

void Tag2Sub20::set_m(const std::string & s){
    mlen = s.size();
    m = s;
}

void Tag2Sub20::set_n(const std::string & s){
    nlen = s.size();
    n = s;
}

Tag2Sub20 * Tag2Sub20::clone(){
    return new Tag2Sub20(*this);
}

#include "Tag2Sub20.h"

Tag2Sub20::Tag2Sub20() :
    Subpacket(20),
    flags(),
    mlen(), nlen(),
    m(), n()
{
}

Tag2Sub20::Tag2Sub20(std::string & data) :
    Tag2Sub20()
{
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

std::string Tag2Sub20::show() const{
    std::stringstream out;
    for(unsigned int x = 0; x < 4; x++){
        out << "            Flag - " << Notation.at(flags[x]) << " (not " << static_cast <unsigned int> (flags[x]) << ")\n";
    }
    out << "\n"
        << "            Name: " << m << "\n"
        << "            Value: " << n << "\n";
    return out.str();
}
std::string Tag2Sub20::raw() const{
    return flags + unhexlify(makehex(m.size(), 4)) + unhexlify(makehex(n.size(), 4)) + m + n;
}

std::string Tag2Sub20::get_flags() const{
    return flags;
}

std::string Tag2Sub20::get_m() const{
    return m;
}

std::string Tag2Sub20::get_n() const{
    return n;
}

void Tag2Sub20::set_flags(const std::string & f){
    if (f.size() != 4){
        throw std::runtime_error("Error: 4 flag octets required.");
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

Subpacket::Ptr Tag2Sub20::clone() const{
    return Ptr(new Tag2Sub20(*this));
}

#include "Sub20.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub20::Sub20()
    : Sub(NOTATION_DATA),
      flags(),
      mlen(), nlen(),
      m(), n()
{}

Sub20::Sub20(const std::string & data)
    : Sub20()
{
    read(data);
}

void Sub20::read(const std::string & data){
    if (data.size()){
        flags = data.substr(0, 4);
        mlen  = toint(data.substr(4, 2), 256);
        nlen  = toint(data.substr(6, 2), 256);
        m     = data.substr(8, mlen);
        n     = data.substr(8 + mlen, nlen);
        size  = 4 + mlen + nlen;
    }
}

std::string Sub20::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');

    std::string out = indent + show_title();
    for(char const & f : flags){
        const decltype(Notation::NAME)::const_iterator not_it = Notation::NAME.find(f);
        out += "\n" + indent + tab + "Flag - " + ((not_it == Notation::NAME.end())?"Unknown":(not_it -> second)) + " (not " + std::to_string(f) + ")";
    }

    return out + "\n" +
                 indent + tab + "Name: " + m + "\n" +
                 indent + tab + "Value: " + n;
}

std::string Sub20::raw() const{
    return flags + unhexlify(makehex(m.size(), 4)) + unhexlify(makehex(n.size(), 4)) + m + n;
}

std::string Sub20::get_flags() const{
    return flags;
}

std::string Sub20::get_m() const{
    return m;
}

std::string Sub20::get_n() const{
    return n;
}

void Sub20::set_flags(const std::string & f){
    if (f.size() != 4){
        throw std::runtime_error("Error: 4 flag octets required.");
    }
    flags = f;
}

void Sub20::set_m(const std::string & s){
    mlen = s.size();
    m = s;
}

void Sub20::set_n(const std::string & s){
    nlen = s.size();
    n = s;
}

Sub::Ptr Sub20::clone() const{
    return std::make_shared <Sub20> (*this);
}

}
}
}
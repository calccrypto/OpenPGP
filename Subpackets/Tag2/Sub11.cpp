#include "Sub11.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub11::Sub11()
    : Sub(PREFERRED_SYMMETRIC_ALGORITHMS),
      psa()
{}

Sub11::Sub11(const std::string & data)
    : Sub11()
{
    read(data);
}

void Sub11::read(const std::string & data){
    psa = data;
    size = data.size();
}

std::string Sub11::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');

    std::string out = indent + show_title();
    for(char const & c : psa){
        const decltype(Sym::NAME)::const_iterator sym_it = Sym::NAME.find(c);
        out += "\n" + indent + tab + "sym alg - " + ((sym_it == Sym::NAME.end())?"Unknown":(sym_it -> second)) + " (sym " + std::to_string(c) + ")";
    }

    return out;
}

std::string Sub11::raw() const{
    return psa;
}

std::string Sub11::get_psa() const{
    return psa;
}

void Sub11::set_psa(const std::string & s){
    psa = s;
}

Sub::Ptr Sub11::clone() const{
    return std::make_shared <Sub11> (*this);
}

}
}
}
#include "Packets/Tag2/Sub11.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub11::actual_read(const std::string & data){
    set_psa(data);
}

void Sub11::show_contents(HumanReadable & hr) const{
    for(char const & c : psa){
        const decltype(Sym::NAME)::const_iterator sym_it = Sym::NAME.find(c);
        hr << std::string("sym alg - ") + ((sym_it == Sym::NAME.end())?"Unknown":(sym_it -> second)) + " (sym " + std::to_string(c) + ")";
    }
}

Sub11::Sub11()
    : Sub(PREFERRED_SYMMETRIC_ALGORITHMS),
      psa()
{}

Sub11::Sub11(const std::string & data)
    : Sub11()
{
    read(data);
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

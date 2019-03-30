#include "Packets/Tag2/Sub11.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub11::actual_read(const std::string & data) {
    set_psa(data);
}

void Sub11::show_contents(HumanReadable & hr) const {
    for(char const & c : psa) {
        hr << std::string("sym alg - ") + get_mapped(Sym::NAME, (uint8_t) c) + " (sym " + std::to_string(c) + ")";
    }
}

Status Sub11::actual_valid(const bool) const {
    for(char const & c : psa) {
        if (Sym::NAME.find(c) == Sym::NAME.end()) {
            return Status::INVALID_SYMMETRIC_ENCRYPTION_ALGORITHM;
        }
    }
    return Status::SUCCESS;
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

std::string Sub11::raw() const {
    return psa;
}

std::string Sub11::get_psa() const {
    return psa;
}

void Sub11::set_psa(const std::string & s) {
    psa = s;
}

Sub::Ptr Sub11::clone() const {
    return std::make_shared <Sub11> (*this);
}

}
}
}

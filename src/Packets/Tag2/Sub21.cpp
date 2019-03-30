#include "Packets/Tag2/Sub21.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub21::actual_read(const std::string & data) {
    set_pha(data);
}

void Sub21::show_contents(HumanReadable & hr) const {
    for(char const & c : pha) {
        hr << "hash alg - " + get_mapped(Hash::NAME, (uint8_t) c) + " (hash " + std::to_string(c) + ")";
    }
}

Status Sub21::actual_valid(const bool) const {
    for(char const & c : pha) {
        if (Hash::NAME.find(c) == Hash::NAME.end()) {
            return Status::INVALID_HASH_ALGORITHM;
        }
    }
    return Status::SUCCESS;
}

Sub21::Sub21()
    : Sub(PREFERRED_HASH_ALGORITHMS),
      pha()
{}

Sub21::Sub21(const std::string & data)
    : Sub21()
{
    read(data);
}

std::string Sub21::raw() const {
    return pha;
}

std::string Sub21::get_pha() const {
    return pha;
}

void Sub21::set_pha(const std::string & p) {
    pha = p;
}

Sub::Ptr Sub21::clone() const {
    return std::make_shared <Sub21> (*this);
}

}
}
}

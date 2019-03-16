#include "Packets/Tag2/Sub21.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub21::actual_read(const std::string & data) {
    set_pha(data);
}

void Sub21::show_contents(HumanReadable & hr) const {
    for(char const & c : pha) {
        const decltype(Hash::NAME)::const_iterator hash_it = Hash::NAME.find(c);
        hr << "hash alg - " + ((hash_it == Hash::NAME.end())?"Unknown":(hash_it -> second)) + " (hash " + std::to_string(c) + ")";
    }
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

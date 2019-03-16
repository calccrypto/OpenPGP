#include "Packets/Tag12.h"

namespace OpenPGP {
namespace Packet {

void Tag12::actual_read(const std::string & data) {
    set_trust(data);
}

void Tag12::show_contents(HumanReadable & hr) const {
    hr << "Data (" + std::to_string(trust.size()) + " octets): " + trust;
}

Tag12::Tag12()
    : Tag(TRUST),
      trust()
{}

Tag12::Tag12(const Tag12 & copy)
    : Tag(copy),
      trust(copy.trust)
{}

Tag12::Tag12(const std::string & data)
    : Tag12()
{
    read(data);
}

std::string Tag12::raw() const {
    return trust;
}

std::string Tag12::get_trust() const {
    return trust;
}

void Tag12::set_trust(const std::string & t) {
    trust = t;
}

Tag::Ptr Tag12::clone() const {
    return std::make_shared <Packet::Tag12> (*this);
}

}
}

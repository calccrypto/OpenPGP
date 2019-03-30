#include "Packets/Tag12.h"

namespace OpenPGP {
namespace Packet {

void Tag12::actual_read(const std::string & data, std::string::size_type & pos, const std::string::size_type & length) {
    set_trust(data.substr(pos, length));
}

void Tag12::show_contents(HumanReadable & hr) const {
    hr << "Data (" + std::to_string(trust.size()) + " octets): " + trust;
}

std::string Tag12::actual_raw() const {
    return trust;
}

Status Tag12::actual_valid(const bool) const {
    return Status::SHOULD_NOT_BE_EMITTED;
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

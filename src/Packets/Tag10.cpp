#include "Packets/Tag10.h"

namespace OpenPGP {
namespace Packet {

const std::string Tag10::body = "PGP";

void Tag10::actual_read(const std::string & data) {
    set_pgp(data);
}

void Tag10::show_contents(HumanReadable & hr) const {
    hr << pgp;
}

std::string Tag10::actual_raw() const {
    return pgp;
}

Error Tag10::actual_valid(const bool) const {
    if (pgp != body) {
        return Error::INVALID_TAG10;
    }

    return Error::SUCCESS;
}

Tag10::Tag10()
    : Tag(MARKER_PACKET),
      pgp(body)
{}

Tag10::Tag10(const Tag10 & copy)
    : Tag(copy),
      pgp(copy.pgp)
{}

Tag10::Tag10(const std::string & data)
    : Tag10()
{
    read(data);
}

std::string Tag10::get_pgp() const {
    return pgp;
}

void Tag10::set_pgp(const std::string & s) {
    pgp = s;
}

Tag::Ptr Tag10::clone() const {
    return std::make_shared <Packet::Tag10> (*this);
}

}
}

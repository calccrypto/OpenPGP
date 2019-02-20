#include "Packets/Partial.h"

namespace OpenPGP {
namespace Packet {

std::string Partial::show_title() const {
    if (partial == PARTIAL) {
        return " (partial)";
    }
    return "";
}

Partial::Partial(const Partial::PartialBodyLength &part)
    : partial(part),
      bits(),
      last(0)
{}

Partial::Partial(const Partial &copy)
    : partial(copy.partial),
      bits(copy.bits),
      last(copy.last)
{}

Partial:: ~Partial() {}

Partial::PartialBodyLength Partial::get_partial() const {
    return partial;
}

void Partial::set_partial(const Partial::PartialBodyLength & part) {
    partial = part;
}

Partial & Partial::operator=(const Partial &copy) {
    partial = copy.partial;
    bits = copy.bits;
    last = copy.last;
    return *this;
}

}
}

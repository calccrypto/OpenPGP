#include "Packets/Partial.h"

namespace OpenPGP {
namespace Packet {

std::string Partial::show_title() const {
    if (partial == PARTIAL) {
        return " (partial)";
    }
    return "";
}

Partial::Partial(const PartialBodyLength &part)
    : partial(part)
{}

Partial::Partial(const Partial &copy)
    : partial(copy.partial)
{}

Partial:: ~Partial() {}

PartialBodyLength Partial::get_partial() const {
    return partial;
}

void Partial::set_partial(const PartialBodyLength & part) {
    partial = part;
}

Partial & Partial::operator=(const Partial &copy) {
    partial = copy.partial;
    return *this;
}

}
}

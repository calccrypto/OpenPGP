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

bool Partial::can_be(const uint8_t tag){
    return ((tag == LITERAL_DATA)                          ||
            (tag == COMPRESSED_DATA)                       ||
            (tag == SYMMETRICALLY_ENCRYPTED_DATA)          ||
            (tag == SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA));
}

bool Partial::can_be(const Tag::Ptr & packet){
    return packet?can_be(packet -> get_tag()):false;
}

Partial & Partial::operator=(const Partial &copy) {
    partial = copy.partial;
    return *this;
}

}
}

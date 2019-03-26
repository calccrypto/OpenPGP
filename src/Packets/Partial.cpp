#include "Packets/Partial.h"

#include "Misc/Length.h"

namespace OpenPGP {
namespace Packet {

std::string Partial::show_title() const {
    if (partial == PARTIAL) {
        return " (partial)";
    }
    return "";
}

std::string Partial::write(const HeaderFormat & header_format, const uint8_t tag, const std::string & data) const {
    if ((header_format == HeaderFormat::NEW) || // specified new header
        (tag > 15)) {                           // tag > 15, so new header is required
        return write_new_length(tag, data, partial);
    }
    return write_old_length(tag, data, partial);
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

bool Partial::can_have_partial_length(const uint8_t tag) {
    return ((tag == LITERAL_DATA)                          ||
            (tag == COMPRESSED_DATA)                       ||
            (tag == SYMMETRICALLY_ENCRYPTED_DATA)          ||
            (tag == SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA));
}

bool Partial::can_have_partial_length(const Tag::Ptr & packet) {
    return packet?can_have_partial_length(packet -> get_tag()):false;
}

Partial & Partial::operator=(const Partial &copy) {
    partial = copy.partial;
    return *this;
}

}
}

#include "Packets/Tag18.h"

namespace OpenPGP {
namespace Packet {

void Tag18::actual_read(const std::string & data) {
    set_version(data[0]);
    set_protected_data(data.substr(1, data.size() - 1));
}

std::string Tag18::show_title() const {
    return Tag::show_title() + Partial::show_title();
}

void Tag18::show_contents(HumanReadable & hr) const {
    hr << "Version: " + std::to_string(version)
       << "Encrypted Data (" + std::to_string(protected_data.size()) + " octets): " + hexlify(protected_data);
}

Tag18::Tag18(const PartialBodyLength & part)
    : Tag(SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA, 1),
      Partial(part),
      protected_data()
{}

Tag18::Tag18(const std::string & data)
    : Tag18()
{
    read(data);
}

std::string Tag18::raw() const {
    return std::string(1, version) + protected_data;
}

std::string Tag18::write() const {
    const std::string data = raw();
    if ((header_format == HeaderFormat::NEW) || // specified new header
        (tag > 15)) {                           // tag > 15, so new header is required
        return write_new_length(tag, data, partial);
    }
    return write_old_length(tag, data, partial);
}

std::string Tag18::get_protected_data() const {
    return protected_data;
}

void Tag18::set_protected_data(const std::string & p) {
    protected_data = p;
}

Tag::Ptr Tag18::clone() const {
    return std::make_shared <Packet::Tag18> (*this);
}

}
}

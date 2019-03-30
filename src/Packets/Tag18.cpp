#include "Packets/Tag18.h"

namespace OpenPGP {
namespace Packet {

void Tag18::actual_read(const std::string & data, std::string::size_type & pos, const std::string::size_type & length) {
    set_version(data[pos + 0]);
    set_protected_data(data.substr(pos + 1, length - 1));
    pos += length;
}

std::string Tag18::show_title() const {
    return Tag::show_title() + Partial::show_title();
}

void Tag18::show_contents(HumanReadable & hr) const {
    hr << "Version: " + std::to_string(version)
       << "Encrypted Data (" + std::to_string(protected_data.size()) + " octets): " + hexlify(protected_data);
}

std::string Tag18::actual_raw() const {
    return std::string(1, version) + protected_data;
}

std::string Tag18::actual_write() const {
    return Partial::write(header_format, tag, raw());
}

Status Tag18::actual_valid(const bool) const {
    if (version != 1) {
        return Status::INVALID_VERSION;
    }

    return Status::SUCCESS;
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

std::string Tag18::write() const {
    return Partial::write(header_format, SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA, raw());
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

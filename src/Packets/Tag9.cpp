#include "Packets/Tag9.h"

namespace OpenPGP {
namespace Packet {

void Tag9::actual_read(const std::string & data) {
    set_encrypted_data(data);
}

std::string Tag9::show_title() const {
    return Tag::show_title() + Partial::show_title();
}

void Tag9::show_contents(HumanReadable & hr) const {
    hr << "Encrypted Data (" + std::to_string(encrypted_data.size()) + " octets): " + hexlify(encrypted_data);
}

Tag9::Tag9(const PartialBodyLength &part)
    : Tag(SYMMETRICALLY_ENCRYPTED_DATA),
      Partial(part),
      encrypted_data()
{}

Tag9::Tag9(const std::string & data)
    : Tag9()
{
    read(data);
}

std::string Tag9::raw() const {
    return encrypted_data;
}

std::string Tag9::write() const {
    const std::string data = raw();
    if ((header_format == HeaderFormat::NEW) || // specified new header
        (tag > 15)) {                           // tag > 15, so new header is required
        return write_new_length(tag, data, partial);
    }
    return write_old_length(tag, data, partial);
}

std::string Tag9::get_encrypted_data() const {
    return encrypted_data;
}

void Tag9::set_encrypted_data(const std::string & e) {
    encrypted_data = e;
}

Tag::Ptr Tag9::clone() const {
    return std::make_shared <Packet::Tag9> (*this);
}

}
}

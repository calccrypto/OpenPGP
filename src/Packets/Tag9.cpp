#include "Packets/Tag9.h"

namespace OpenPGP {
namespace Packet {

void Tag9::actual_read(const std::string & data, std::string::size_type & pos, const std::string::size_type & length) {
    set_encrypted_data(data.substr(pos, length));
    pos += length;
}

std::string Tag9::show_title() const {
    return Tag::show_title() + Partial::show_title();
}

void Tag9::show_contents(HumanReadable & hr) const {
    hr << "Encrypted Data (" + std::to_string(encrypted_data.size()) + " octets): " + hexlify(encrypted_data);
}

std::string Tag9::actual_raw() const {
    return encrypted_data;
}

std::string Tag9::actual_write() const {
    return Partial::write(header_format, tag, raw());
}

Status Tag9::actual_valid(const bool) const {
    if (encrypted_data.size() < 2) {
        return Status::INVALID_LENGTH;
    }

    return Status::SUCCESS;
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

std::string Tag9::write(Status * status, const bool check_mpi) const {
    if (status && ((*status = valid(check_mpi)) != Status::SUCCESS)) {
        return "";
    }

    return Partial::write(header_format, SYMMETRICALLY_ENCRYPTED_DATA, raw());
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

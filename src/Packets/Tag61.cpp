#include "Packets/Tag61.h"

namespace OpenPGP {
namespace Packet {

void Tag61::actual_read(const std::string & data, std::string::size_type & pos, const std::string::size_type & length) {
    set_stream(data.substr(pos, length));
    pos += length;
}

void Tag61::show_contents(HumanReadable & hr) const {
    hr << hexlify(stream);
}

std::string Tag61::actual_raw() const {
    return stream;
}

Status Tag61::actual_valid(const bool) const {
    return Status::SUCCESS;
}

Tag61::Tag61()
    : Tag61(std::string())
{}

Tag61::Tag61(const std::string & data)
    : Tag(61),
      stream()
{
    read(data);
}

std::string Tag61::get_stream() const {
    return stream;
}

void Tag61::set_stream(const std::string & data) {
    stream = data;
}

Tag::Ptr Tag61::clone() const {
    return std::make_shared <Packet::Tag61> (*this);
}

}

}

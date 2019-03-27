#include "Packets/Tag63.h"

namespace OpenPGP {
namespace Packet {

void Tag63::actual_read(const std::string & data, std::string::size_type & pos, const std::string::size_type & length) {
    set_stream(data.substr(pos, length));
    pos += length;
}

void Tag63::show_contents(HumanReadable & hr) const {
    hr << hexlify(stream);
}

std::string Tag63::actual_raw() const {
    return stream;
}

Tag63::Tag63()
    : Tag63(std::string())
{}

Tag63::Tag63(const std::string & data)
    : Tag(63),
      stream()
{
    read(data);
}

std::string Tag63::get_stream() const {
    return stream;
}

void Tag63::set_stream(const std::string & data) {
    stream = data;
}

Tag::Ptr Tag63::clone() const {
    return std::make_shared <Packet::Tag63> (*this);
}

}

}

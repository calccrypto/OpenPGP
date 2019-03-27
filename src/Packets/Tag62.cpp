#include "Packets/Tag62.h"

namespace OpenPGP {
namespace Packet {

void Tag62::actual_read(const std::string & data, std::string::size_type & pos, const std::string::size_type & length) {
    set_stream(data.substr(pos, length));
    pos += length;
}

void Tag62::show_contents(HumanReadable & hr) const {
    hr << hexlify(stream);
}

std::string Tag62::actual_raw() const {
    return stream;
}

Tag62::Tag62()
    : Tag62(std::string())
{}

Tag62::Tag62(const std::string & data)
    : Tag(62),
      stream()
{
    read(data);
}

std::string Tag62::get_stream() const {
    return stream;
}

void Tag62::set_stream(const std::string & data) {
    stream = data;
}

Tag::Ptr Tag62::clone() const {
    return std::make_shared <Packet::Tag62> (*this);
}

}

}

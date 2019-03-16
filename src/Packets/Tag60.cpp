#include "Packets/Tag60.h"

#include "common/includes.h"

namespace OpenPGP {
namespace Packet {

void Tag60::actual_read(const std::string & data) {
    stream = data;
}

void Tag60::show_contents(HumanReadable & hr) const {
    hr << hexlify(stream);
}

Tag60::Tag60()
    : Tag60(std::string())
{}

Tag60::Tag60(const std::string & data)
    : Tag(60),
      stream()
{
    read(data);
}

std::string Tag60::raw() const {
    return stream;
}

std::string Tag60::get_stream() const {
    return stream;
}

void Tag60::set_stream(const std::string & data) {
    stream = data;
}

Tag::Ptr Tag60::clone() const {
    return std::make_shared <Packet::Tag60> (*this);
}

}

}

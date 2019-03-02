#include "Packets/Tag62.h"

#include "common/includes.h"

namespace OpenPGP {
namespace Packet {

void Tag62::actual_read(const std::string & data){
    stream = data;
}

void Tag62::show_contents(HumanReadable & hr) const{
    hr << hexlify(stream);
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

std::string Tag62::raw() const{
    return stream;
}

std::string Tag62::get_stream() const{
    return stream;
}

void Tag62::set_stream(const std::string & data){
    stream = data;
}

Tag::Ptr Tag62::clone() const{
    return std::make_shared <Packet::Tag62> (*this);
}

}

}

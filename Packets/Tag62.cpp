#include "Tag62.h"

namespace OpenPGP {
namespace Packet {

Tag62::Tag62()
    : Tag62(std::string())
{}

Tag62::Tag62(const Tag62 & copy)
    : Tag(copy),
      stream(copy.stream)
{}

Tag62::Tag62(const std::string & data)
    : Tag(62),
      stream(data)
{}

void Tag62::read(const std::string & data){
    stream = data;
}

std::string Tag62::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" + 
           indent + tab + hexlify(stream);
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
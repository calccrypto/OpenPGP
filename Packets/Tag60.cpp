#include "Tag60.h"

namespace OpenPGP {
namespace Packet {

Tag60::Tag60()
    : Tag60(std::string())
{}

Tag60::Tag60(const Tag60 & copy)
    : Tag(copy),
      stream(copy.stream)
{}

Tag60::Tag60(const std::string & data)
    : Tag(60),
      stream(data)
{}

void Tag60::read(const std::string & data){
    stream = data;
}

std::string Tag60::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + hexlify(stream);
}

std::string Tag60::raw() const{
    return stream;
}

std::string Tag60::get_stream() const{
    return stream;
}

void Tag60::set_stream(const std::string & data){
    stream = data;
}

Tag::Ptr Tag60::clone() const{
    return std::make_shared <Packet::Tag60> (*this);
}

}

}
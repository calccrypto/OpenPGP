#include "Tag19.h"

namespace OpenPGP {
namespace Packet {

Tag19::Tag19()
    : Tag(MODIFICATION_DETECTION_CODE),
      hash()
{
    size = 20;
}

Tag19::Tag19(const Tag19 & copy)
    : Tag(copy),
      hash(copy.hash)
{}

Tag19::Tag19(const std::string & data)
    : Tag19()
{
    read(data);
}

void Tag19::read(const std::string & data){
    size = data.size();
    hash = data;
}

std::string Tag19::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "SHA - 1 Hash of previous packet: " + hash;
}

std::string Tag19::raw() const{
    return hash;
}

std::string Tag19::get_hash() const{
    return hash;
}

void Tag19::set_hash(const std::string & h){
    hash = h;
    size = raw().size();
}

Tag::Ptr Tag19::clone() const{
    return std::make_shared <Packet::Tag19> (*this);
}

}

}
#include "Tag12.h"

namespace OpenPGP {
namespace Packet {

Tag12::Tag12()
    : Tag(TRUST),
      trust()
{}

Tag12::Tag12(const Tag12 & copy)
    : Tag(copy),
      trust(copy.trust)
{}

Tag12::Tag12(const std::string & data)
    : Tag12()
{
    read(data);
}

void Tag12::read(const std::string & data){
    size = data.size();
    trust = data;
}

std::string Tag12::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "Data (" + std::to_string(trust.size()) + " octets): " + trust;
}

std::string Tag12::raw() const{
    return trust;
}

std::string Tag12::get_trust() const{
    return trust;
}

void Tag12::set_trust(const std::string & t){
    trust = t;
    size = raw().size();
}

Tag::Ptr Tag12::clone() const{
    return std::make_shared <Packet::Tag12> (*this);
}

}
}
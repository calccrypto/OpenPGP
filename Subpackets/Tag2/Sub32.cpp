#include "Sub32.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub32::Sub32()
    : Sub(EMBEDDED_SIGNATURE),
      embedded(nullptr)
{}

Sub32::Sub32(const Sub32 & copy)
    : Sub(copy),
      embedded(std::static_pointer_cast <Packet::Tag2> (copy.embedded -> clone()))
{}

Sub32::Sub32(const std::string & data)
    : Sub32()
{
    read(data);
}

Sub32::~Sub32(){}

void Sub32::read(const std::string & data){
    embedded = std::make_shared <Packet::Tag2> (data);
    size = data.size();
}

std::string Sub32::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indent_size, ' ');
    const std::string tab(indents * indent_size, ' ');
    return tab + show_title() + "\n" +
           embedded -> show(indents + 1, indent_size);
}

std::string Sub32::raw() const{
    return embedded -> raw();
}

Packet::Tag2::Tag::Ptr Sub32::get_embedded() const{
    return embedded;
}

void Sub32::set_embedded(const Packet::Tag2::Ptr & e){
    embedded = std::static_pointer_cast <Packet::Tag2> (e -> clone());
}

Sub::Ptr Sub32::clone() const{
    return std::make_shared <Sub32> (*this);
}

Sub32 & Sub32::operator=(const Sub32 & copy){
    Sub::operator=(copy);
    embedded = std::static_pointer_cast <Packet::Tag2> (copy.embedded -> clone());
    return *this;
}

}
}
}

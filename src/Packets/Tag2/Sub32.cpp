#include "Packets/Tag2/Sub32.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub32::actual_read(const std::string & data) {
    set_embedded(std::make_shared <Packet::Tag2> (data), true);
}

void Sub32::show_contents(HumanReadable & hr) const {
    if (embedded) {
        embedded -> show(hr);
    }
}

Sub32::Sub32()
    : Sub(EMBEDDED_SIGNATURE),
      embedded(nullptr)
{}

Sub32::Sub32(const Sub32 & copy)
    : Sub(copy)
{
    set_embedded(copy.embedded);
}

Sub32::Sub32(const std::string & data)
    : Sub32()
{
    read(data);
}

Sub32::~Sub32() {}

std::string Sub32::raw() const {
    return embedded?(embedded -> raw()):"";
}

Packet::Tag2::Tag::Ptr Sub32::get_embedded() const {
    return embedded;
}

void Sub32::set_embedded(const Packet::Tag2::Ptr & e, const bool copy) {
    embedded = e;
    if (embedded && !copy) {
        embedded = std::static_pointer_cast <Packet::Tag2> (embedded -> clone());
    }
}

Sub::Ptr Sub32::clone() const {
    return std::make_shared <Sub32> (*this);
}

Sub32 & Sub32::operator=(const Sub32 & copy) {
    Sub::operator=(copy);
    set_embedded(copy.embedded);
    return *this;
}

}
}
}

#include "Tag12.h"

Tag12::Tag12()
    : Packet(Packet::ID::Trust),
      trust()
{}

Tag12::Tag12(const Tag12 & copy)
    : Packet(copy),
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

std::string Tag12::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string tab(indents * indent_size, ' ');
    return tab + show_title() + "\n" + tab + "    Data (" + std::to_string(trust.size()) + " octets): " + trust;
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

Packet::Ptr Tag12::clone() const{
    return std::make_shared <Tag12> (*this);
}

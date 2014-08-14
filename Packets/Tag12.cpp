#include "Tag12.h"

Tag12::Tag12():
    Packet(12),
    trust()
{}

Tag12::Tag12(std::string & data):
    Tag12()
{
    read(data);
}

void Tag12::read(std::string & data, const uint8_t part){
    size = data.size();
    trust = data;
}

std::string Tag12::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::stringstream out;
    out << std::string(tab, ' ') << show_title() << "\n" << std::string(tab, ' ') << "    Data (" << trust.size() << " octets): " << trust;
    return out.str();
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

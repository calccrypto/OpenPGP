#include "Tag12.h"

Tag12::Tag12() :
    Packet(12),
    trust()
{
}

Tag12::Tag12(std::string & data) :
    Tag12()
{
    read(data);
}

void Tag12::read(std::string & data){
    size = data.size();
    trust = data;
}

std::string Tag12::show(const uint8_t indent) const{
    std::stringstream out;
    out << std::string(indent, ' ') << show_title(indent) << std::string(indent, ' ') << "    Data (" << trust.size() << " octets): " << trust << "\n";
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
    return Ptr(new Tag12(*this));
}

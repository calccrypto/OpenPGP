#include "Tag19.h"

Tag19::Tag19():
    Packet(19),
    hash()
{
    size = 20;
}

Tag19::Tag19(std::string & data):
    Tag19()
{
    read(data);
}

void Tag19::read(std::string & data, const uint8_t part){
    size = data.size();
    hash = data;
}

std::string Tag19::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::stringstream out;
    out << std::string(tab, ' ') << show_title() << "\n" << std::string(tab, ' ') << "    SHA - 1 Hash of previous packet: " << hash;
    return out.str();
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

Packet::Ptr Tag19::clone() const{
    return std::make_shared <Tag19> (*this);
}

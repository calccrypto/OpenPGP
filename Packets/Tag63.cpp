#include "Tag63.h"

Tag63::Tag63():
    Tag63(std::string())
{}

Tag63::Tag63(const std::string & data):
    Packet(),
    stream(data)
{}

void Tag63::read(std::string & data, const uint8_t part){
    stream = data;
}

std::string Tag63::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    return std::string(tab, ' ') + std::string(tab, ' ') + show_title() + "\n" + std::string(tab + indent_size, ' ') + hexlify(stream);
}

std::string Tag63::raw() const{
    return stream;
}

std::string Tag63::get_stream() const{
    return stream;
}

void Tag63::set_stream(const std::string & data){
    stream = data;
}

Packet::Ptr Tag63::clone() const{
    return std::make_shared <Tag63> (*this);
}

#include "Tag62.h"

Tag62::Tag62():
    Tag62(std::string())
{}

Tag62::Tag62(const std::string & data):
    Packet(),
    stream(data)
{}

void Tag62::read(std::string & data){
    stream = data;
}

std::string Tag62::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string tab(indents * indent_size, ' ');
    return tab + tab + show_title() + "\n" + std::string((indents  + 1) * indent_size, ' ') + hexlify(stream);
}

std::string Tag62::raw() const{
    return stream;
}

std::string Tag62::get_stream() const{
    return stream;
}

void Tag62::set_stream(const std::string & data){
    stream = data;
}

Packet::Ptr Tag62::clone() const{
    return std::make_shared <Tag62> (*this);
}

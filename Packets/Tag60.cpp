#include "Tag60.h"

Tag60::Tag60():
    Tag60(std::string())
{}

Tag60::Tag60(const std::string & data):
    Packet(),
    stream(data)
{}

void Tag60::read(std::string & data){
    stream = data;
}

std::string Tag60::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string tab(indents * indent_size, ' ');
    return tab + tab + show_title() + "\n" + std::string((indents  + 1) * indent_size, ' ') + hexlify(stream);
}

std::string Tag60::raw() const{
    return stream;
}

std::string Tag60::get_stream() const{
    return stream;
}

void Tag60::set_stream(const std::string & data){
    stream = data;
}

Packet::Ptr Tag60::clone() const{
    return std::make_shared <Tag60> (*this);
}

#include "Tag61.h"

Tag61::Tag61()
    : Tag61(std::string())
{}

Tag61::Tag61(const std::string & data)
    : Packet(),
      stream(data)
{}

void Tag61::read(const std::string & data){
    stream = data;
}

std::string Tag61::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string tab(indents * indent_size, ' ');
    return tab + tab + show_title() + "\n" + std::string((indents  + 1) * indent_size, ' ') + hexlify(stream);
}

std::string Tag61::raw() const{
    return stream;
}

std::string Tag61::get_stream() const{
    return stream;
}

void Tag61::set_stream(const std::string & data){
    stream = data;
}

Packet::Ptr Tag61::clone() const{
    return std::make_shared <Tag61> (*this);
}

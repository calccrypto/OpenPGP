#include "Partial.h"

Partial::Partial():
    Partial(std::string())
{}

Partial::Partial(const std::string & data):
    Packet(),
    stream(data)
{}

void Partial::read(std::string & data, const uint8_t part){
    stream = data;
}

std::string Partial::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    return std::string(tab, ' ') + std::string(tab, ' ') + show_title() + "\n" + std::string(tab + indent_size, ' ') + hexlify(stream);
}

std::string Partial::raw() const{
    return stream;
}

std::string Partial::get_stream() const{
    return stream;
}

void Partial::set_stream(const std::string & data){
    stream = data;
}

Packet::Ptr Partial::clone() const{
    return Ptr(new Partial(*this));
}

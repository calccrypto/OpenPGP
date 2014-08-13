#include "TagX.h"

TagX::TagX():
    TagX(std::string())
{}

TagX::TagX(const std::string & data):
    Packet(),
    stream(data)
{}

void TagX::read(std::string & data){
    stream = data;
}

std::string TagX::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    return std::string(tab, ' ') + std::string(tab, ' ') + show_title() + "\n" + std::string(tab + indent_size, ' ') + hexlify(stream);
}

std::string TagX::raw() const{
    return stream;
}

std::string TagX::get_stream() const{
    return stream;
}

void TagX::set_stream(const std::string & data){
    stream = data;
}

Packet::Ptr TagX::clone() const{
    return Ptr(new TagX(*this));
}

#include "Tag2Sub26.h"

Tag2Sub26::Tag2Sub26():
    Tag2Subpacket(26),
    uri()
{}

Tag2Sub26::Tag2Sub26(std::string & data):
    Tag2Sub26()
{
    read(data);
}

void Tag2Sub26::read(std::string & data){
    uri = data;
    size = data.size();
}

std::string Tag2Sub26::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    return std::string(tab, ' ') + show_title() + "\n" + std::string(tab, ' ') + "            Policy - " + uri;
}

std::string Tag2Sub26::raw() const{
    return uri;
}

std::string Tag2Sub26::get_uri() const{
    return uri;
}

void Tag2Sub26::set_uri(const std::string & u){
    uri = u;
}

Tag2Subpacket::Ptr Tag2Sub26::clone() const{
    return std::make_shared <Tag2Sub26> (*this);
}

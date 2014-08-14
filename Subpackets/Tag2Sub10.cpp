#include "Tag2Sub10.h"

Tag2Sub10::Tag2Sub10():
    Tag2Subpacket(10),
    stuff()
{}

Tag2Sub10::Tag2Sub10(std::string & data):
    Tag2Sub10()
{
    read(data);
}

void Tag2Sub10::read(std::string & data){
    stuff = data;
    size = data.size();
}

std::string Tag2Sub10::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    return std::string(tab, ' ') + show_title() + "\n" + std::string(tab, ' ') + stuff;
}

std::string Tag2Sub10::raw() const{
    return stuff;
}

std::string Tag2Sub10::get_stuff() const{
    return stuff;
}

void Tag2Sub10::set_stuff(const std::string & s){
    stuff = s;
}

Tag2Subpacket::Ptr Tag2Sub10::clone() const{
    return std::make_shared <Tag2Sub10> (*this);
}

#include "Tag2Sub10.h"

Tag2Sub10::Tag2Sub10()
    : Tag2Subpacket(Tag2Subpacket::PLACEHOLDER_FOR_BACKWARD_COMPATIBILITY),
      stuff()
{}

Tag2Sub10::Tag2Sub10(const std::string & data)
    : Tag2Sub10()
{
    read(data);
}

void Tag2Sub10::read(const std::string & data){
    stuff = data;
    size = data.size();
}

std::string Tag2Sub10::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + stuff;
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

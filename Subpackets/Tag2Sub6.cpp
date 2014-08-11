#include "Tag2Sub6.h"

Tag2Sub6::Tag2Sub6() :
    Subpacket(6),
    regex()
{}

Tag2Sub6::Tag2Sub6(std::string & data) :
    Tag2Sub6()
{
    read(data);
}

void Tag2Sub6::read(std::string & data){
    regex = data;
    size = data.size();
}

std::string Tag2Sub6::show(const uint8_t indents, const uint8_t indent_size) const{
    return std::string(indents * indent_size, ' ') + "            Regular Expression: " + regex + "\n";
}

std::string Tag2Sub6::raw() const{
    return regex + zero; // might not need '+ zero'
}

std::string Tag2Sub6::get_regex() const{
    return regex;
}

void Tag2Sub6::set_regex(const std::string & r){
    regex = r;
}

Subpacket::Ptr Tag2Sub6::clone() const{
    return Ptr(new Tag2Sub6(*this));
}

#include "Tag2Sub6.h"

Tag2Sub6::Tag2Sub6()
    : Tag2Subpacket(Tag2Subpacket::REGULAR_EXPRESSION),
      regex()
{}

Tag2Sub6::Tag2Sub6(const std::string & data)
    : Tag2Sub6()
{
    read(data);
}

void Tag2Sub6::read(const std::string & data){
    regex = data;
    size = data.size();
}

std::string Tag2Sub6::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "Regular Expression: " + regex;
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

Tag2Subpacket::Ptr Tag2Sub6::clone() const{
    return std::make_shared <Tag2Sub6> (*this);
}

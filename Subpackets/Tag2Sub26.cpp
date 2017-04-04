#include "Tag2Sub26.h"

Tag2Sub26::Tag2Sub26()
    : Tag2Subpacket(Tag2Subpacket::POLICY_URI),
      uri()
{}

Tag2Sub26::Tag2Sub26(const std::string & data)
    : Tag2Sub26()
{
    read(data);
}

void Tag2Sub26::read(const std::string & data){
    uri = data;
    size = data.size();
}

std::string Tag2Sub26::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" + 
           indent + tab + "Policy - " + uri;
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

#include "Tag2Sub24.h"

Tag2Sub24::Tag2Sub24()
    : Tag2Subpacket(Tag2Subpacket::PREFERRED_KEY_SERVER),
      pks()
{}

Tag2Sub24::Tag2Sub24(const std::string & data)
    : Tag2Sub24()
{
    read(data);
}

void Tag2Sub24::read(const std::string & data){
    pks = data;
    size = data.size();
}

std::string Tag2Sub24::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "URI - " + pks;
}

std::string Tag2Sub24::raw() const{
    return pks;
}

std::string Tag2Sub24::get_pks() const{
    return pks;
}

void Tag2Sub24::set_pks(const std::string & p){
    pks = p;
}

Tag2Subpacket::Ptr Tag2Sub24::clone() const{
    return std::make_shared <Tag2Sub24> (*this);
}

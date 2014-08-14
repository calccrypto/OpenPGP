#include "Tag2Sub24.h"

Tag2Sub24::Tag2Sub24():
    Tag2Subpacket(24),
    pks()
{}

Tag2Sub24::Tag2Sub24(std::string & data):
    Tag2Sub24()
{
    read(data);
}

void Tag2Sub24::read(std::string & data){
    pks = data;
    size = data.size();
}

std::string Tag2Sub24::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    return std::string(tab, ' ') + show_title() + "\n" + std::string(tab, ' ') + "            URI - " + pks;
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

#include "Tag2Sub32.h"

Tag2Sub32::Tag2Sub32() :
    Subpacket(32),
    embedded()
{
}

Tag2Sub32::Tag2Sub32(const Tag2Sub32 & copy) :
    Subpacket(copy),
    embedded(std::dynamic_pointer_cast<Tag2>(copy.embedded -> clone()))
{
}

Tag2Sub32::Tag2Sub32(std::string & data) :
    Tag2Sub32()
{
    read(data);
}

Tag2Sub32::~Tag2Sub32(){
}

void Tag2Sub32::read(std::string & data){
    embedded = std::make_shared<Tag2>();
    embedded -> read(data);
    size = data.size();
}

std::string Tag2Sub32::show(const uint8_t indent) const{
    return embedded -> show();
}

std::string Tag2Sub32::raw() const{
    return embedded -> raw();
}

Tag2::Ptr Tag2Sub32::get_embedded() const{
    return embedded;
}

void Tag2Sub32::set_embedded(const Tag2::Ptr & e){
    embedded = std::dynamic_pointer_cast<Tag2>(e -> clone());
}

Subpacket::Ptr Tag2Sub32::clone() const{
    return Ptr(new Tag2Sub32(*this));
}

Tag2Sub32 & Tag2Sub32::operator=(const Tag2Sub32 & copy){
    Subpacket::operator =(copy);
    embedded = std::dynamic_pointer_cast<Tag2>(copy.embedded -> clone());
    return *this;
}

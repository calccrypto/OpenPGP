#include "Tag2Sub26.h"

Tag2Sub26::Tag2Sub26() :
    Subpacket(26),
    uri()
{
}

Tag2Sub26::Tag2Sub26(std::string & data) :
    Tag2Sub26()
{
    read(data);
}

void Tag2Sub26::read(std::string & data){
    uri = data;
    size = data.size();
}

std::string Tag2Sub26::show(){
    return "            Policy - " + uri;
}

std::string Tag2Sub26::raw(){
    return uri;
}

std::string Tag2Sub26::get_uri(){
    return uri;
}

void Tag2Sub26::set_uri(const std::string & u){
    uri = u;
}

Subpacket::Ptr Tag2Sub26::clone() const{
    return Ptr(new Tag2Sub26(*this));
}

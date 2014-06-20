#include "Tag2Sub10.h"

Tag2Sub10::Tag2Sub10() :
    Subpacket(10),
    stuff()
{
}

Tag2Sub10::Tag2Sub10(std::string & data) :
    Tag2Sub10()
{
    read(data);
}

void Tag2Sub10::read(std::string & data){
    stuff = data;
    size = data.size();
}

std::string Tag2Sub10::show(){
    return stuff;
}

std::string Tag2Sub10::raw(){
    return stuff;
}

std::string Tag2Sub10::get_stuff(){
    return stuff;
}

void Tag2Sub10::set_stuff(const std::string & s){
    stuff = s;
}

Subpacket::Ptr Tag2Sub10::clone() const{
    return Ptr(new Tag2Sub10(*this));
}

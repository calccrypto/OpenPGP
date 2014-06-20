#include "Tag2Sub25.h"
Tag2Sub25::Tag2Sub25(){
    type = 25;
    size = 1;
}

Tag2Sub25::Tag2Sub25(std::string & data){
    type = 25;
    read(data);
}

void Tag2Sub25::read(std::string & data){
    primary = data[0];
}

std::string Tag2Sub25::show(){
    return std::string("            Primary: ") + (primary?"True":"False") + "\n";
}

std::string Tag2Sub25::raw(){
    return (primary?"\x01":zero);
}

bool Tag2Sub25::get_primary(){
    return primary;
}

void Tag2Sub25::set_primary(const bool p){
    primary = p;
}

Subpacket::Ptr Tag2Sub25::clone(){
    return Ptr(new Tag2Sub25(*this));
}

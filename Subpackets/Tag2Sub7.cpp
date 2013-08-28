#include "Tag2Sub7.h"
Tag2Sub7::Tag2Sub7(){
    type = 7;
    size = 1;
}

Tag2Sub7::Tag2Sub7(std::string & data){
    type = 7;
    size = 1;
    read(data);
}

void Tag2Sub7::read(std::string & data){
    revocable = data[0];
}

std::string Tag2Sub7::show(){
    return std::string("            Revocable: ") + (revocable?"True":"False") + "\n";
}

std::string Tag2Sub7::raw(){
    return (revocable?"\x01":zero);
}

Tag2Sub7 * Tag2Sub7::clone(){
    return new Tag2Sub7(*this);
}

bool Tag2Sub7::get_revocable(){
    return revocable;
}

void Tag2Sub7::set_revocable(bool r){
    revocable = r;
}

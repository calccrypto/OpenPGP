#include "Tag2Sub24.h"
Tag2Sub24::Tag2Sub24(){
    type = 24;
}

Tag2Sub24::Tag2Sub24(std::string & data){
    type = 24;
    read(data);
}

void Tag2Sub24::read(std::string & data){
    pks = data;
    size = data.size();
}

std::string Tag2Sub24::show(){
    return "            URI - " + pks;
}

std::string Tag2Sub24::raw(){
    return pks;
}

Tag2Sub24 * Tag2Sub24::clone(){
    return new Tag2Sub24(*this);
}

std::string Tag2Sub24::get_pks(){
    return pks;
}

void Tag2Sub24::set_pks(const std::string & p){
    pks = p;
}

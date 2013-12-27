#include "Tag2Sub32.h"
Tag2Sub32::Tag2Sub32(){
    type = 32;
    embedded = NULL;
}

Tag2Sub32::Tag2Sub32(std::string & data){
    type = 32;
    embedded = NULL;
    read(data);
}

void Tag2Sub32::read(std::string & data){
    embedded = new Tag2;
    embedded -> read(data);
    size = data.size();
}

std::string Tag2Sub32::show(){
    return embedded -> show();
}

std::string Tag2Sub32::raw(){
    return embedded -> raw();
}

Tag2Sub32 * Tag2Sub32::clone(){
    return new Tag2Sub32(*this);
}

Tag2 * Tag2Sub32::get_embedded(){
    return embedded;
}

void Tag2Sub32::set_embedded(Tag2 * e){
    embedded = e -> clone();
}

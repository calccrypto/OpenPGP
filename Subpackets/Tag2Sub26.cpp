#include "Tag2Sub26.h"
Tag2Sub26::Tag2Sub26(){
    type = 26;
}

Tag2Sub26::Tag2Sub26(std::string & data){
    type = 26;
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

Tag2Sub26 * Tag2Sub26::clone(){
    return new Tag2Sub26(*this);
}

std::string Tag2Sub26::get_uri(){
    return uri;
}

void Tag2Sub26::set_uri(std::string u){
    uri = u;
}

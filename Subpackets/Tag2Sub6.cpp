#include "Tag2Sub6.h"
Tag2Sub6::Tag2Sub6(){
    type = 6;
}

Tag2Sub6::Tag2Sub6(std::string & data){
    type = 6;
    read(data);
}

void Tag2Sub6::read(std::string & data){
    regex = data;
    size = data.size();
}

std::string Tag2Sub6::show(){
    return "            Regular Expression: " + regex + "\n";
}

std::string Tag2Sub6::raw(){
    return regex + zero; // might not need '+ zero'
}

Tag2Sub6 * Tag2Sub6::clone(){
    return new Tag2Sub6(*this);
}

std::string Tag2Sub6::get_regex(){
    return regex;
}

void Tag2Sub6::set_regex(std::string r){
    regex = r;
}

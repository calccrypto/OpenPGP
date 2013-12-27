#include "Tag2Sub2.h"
Tag2Sub2::Tag2Sub2(){
    type = 2;
    size = 4;
}

Tag2Sub2::Tag2Sub2(std::string & data){
    type = 2;
    read(data);
}

void Tag2Sub2::read(std::string & data){
    time = toint(data, 256);
}

std::string Tag2Sub2::show(){
    return "            Creation Time: " + show_time(time) + "\n";
}

std::string Tag2Sub2::raw(){
    return unhexlify(makehex((uint32_t) time, 8));
}

Tag2Sub2 * Tag2Sub2::clone(){
    return new Tag2Sub2(*this);
}

time_t Tag2Sub2::get_time(){
    return time;
}

void Tag2Sub2::set_time(const time_t t){
    time = t;
}

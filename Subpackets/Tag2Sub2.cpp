#include "Tag2Sub2.h"

Tag2Sub2::Tag2Sub2() :
    Subpacket(2, 4),
    time()
{
}

Tag2Sub2::Tag2Sub2(std::string & data) :
    Tag2Sub2()
{
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

time_t Tag2Sub2::get_time(){
    return time;
}

void Tag2Sub2::set_time(const time_t t){
    time = t;
}

Subpacket::Ptr Tag2Sub2::clone() const{
    return Ptr(new Tag2Sub2(*this));
}

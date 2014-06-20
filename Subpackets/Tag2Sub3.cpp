#include "Tag2Sub3.h"

Tag2Sub3::Tag2Sub3() :
    Subpacket(3, 4)
{
}

Tag2Sub3::Tag2Sub3(std::string & data) :
    Tag2Sub3()
{
    read(data);
}

void Tag2Sub3::read(std::string & data){
    time = toint(data, 256);
}

std::string Tag2Sub3::show(){
    std::stringstream out;
    out << "            Signature Expiration Time (Days): ";
    if (time == 0)
            out << "Never\n";
    else
            out << show_time(time);
    out << "\n";
    return out.str();
}

std::string Tag2Sub3::raw(){
    return unhexlify(makehex(time, 8));
}

time_t Tag2Sub3::get_time(){
    return time;
}

void Tag2Sub3::set_time(const time_t t){
    time = t;
}

Subpacket::Ptr Tag2Sub3::clone() const{
    return Ptr(new Tag2Sub3(*this));
}

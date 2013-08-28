#include "Tag2Sub3.h"
Tag2Sub3::Tag2Sub3(){
    type = 3;
    size = 4;
}

Tag2Sub3::Tag2Sub3(std::string & data){
    type = 3;
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

Tag2Sub3 * Tag2Sub3::clone(){
    return new Tag2Sub3(*this);
}

time_t Tag2Sub3::get_time(){
    return time;
}

void Tag2Sub3::set_time(time_t t){
    time = t;
}

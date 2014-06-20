#include "Tag2Sub9.h"

Tag2Sub9::Tag2Sub9() :
    Subpacket(9, 4),
    time()
{
}

Tag2Sub9::Tag2Sub9(std::string & data) :
    Tag2Sub9()
{
    read(data);
}

void Tag2Sub9::read(std::string & data){
    time = (time_t) toint(data, 256);
}

std::string Tag2Sub9::show(){
    std::stringstream out;
    out << "            Key Expiration Time (Days): ";
    if (time == 0){
            out << "Never\n";
    }
    else{
            out << show_time(time);
    }
    out << "\n";
    return out.str();
}

std::string Tag2Sub9::raw(){
    return unhexlify(makehex(time, 8));
}

time_t Tag2Sub9::get_time(){
    return time;
}

void Tag2Sub9::set_time(const time_t t){
    time = t;
}

Subpacket::Ptr Tag2Sub9::clone() const{
    return Ptr(new Tag2Sub9(*this));
}

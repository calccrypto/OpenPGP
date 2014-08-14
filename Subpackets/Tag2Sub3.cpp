#include "Tag2Sub3.h"

Tag2Sub3::Tag2Sub3():
    Tag2Subpacket(3, 4),
    time(0)
{}

Tag2Sub3::Tag2Sub3(std::string & data):
    Tag2Sub3()
{
    read(data);
}

void Tag2Sub3::read(std::string & data){
    time = toint(data, 256);
}

std::string Tag2Sub3::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::stringstream out;
    out << std::string(tab, ' ') << show_title() << "\n"
        << std::string(tab, ' ') << "            Signature Expiration Time (Days): ";
    if (time == 0){
        out << std::string(tab, ' ') << "Never";
    }
    else{
        out << std::string(tab, ' ') << show_time(time);
    }
    return out.str();
}

std::string Tag2Sub3::raw() const{
    return unhexlify(makehex(time, 8));
}

time_t Tag2Sub3::get_time() const{
    return time;
}

void Tag2Sub3::set_time(const time_t t){
    time = t;
}

Tag2Subpacket::Ptr Tag2Sub3::clone() const{
    return std::make_shared <Tag2Sub3> (*this);
}

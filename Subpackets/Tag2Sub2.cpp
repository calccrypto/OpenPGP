#include "Tag2Sub2.h"

Tag2Sub2::Tag2Sub2():
    Tag2Subpacket(2, 4),
    time()
{}

Tag2Sub2::Tag2Sub2(std::string & data):
    Tag2Sub2()
{
    read(data);
}

void Tag2Sub2::read(std::string & data){
    time = toint(data, 256);
}

std::string Tag2Sub2::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    return std::string(tab, ' ') + show_title() + "\n" + std::string(tab, ' ') + "            Creation Time: " + show_time(time);
}

std::string Tag2Sub2::raw() const{
    return unhexlify(makehex(static_cast <uint32_t> (time), 8));
}

time_t Tag2Sub2::get_time() const{
    return time;
}

void Tag2Sub2::set_time(const time_t t){
    time = t;
}

Tag2Subpacket::Ptr Tag2Sub2::clone() const{
    return std::make_shared <Tag2Sub2> (*this);
}

#include "Tag2Sub3.h"

Tag2Sub3::Tag2Sub3()
    : Tag2Subpacket(Tag2Subpacket::ID::Signature_Expiration_Time, 4),
      time(0)
{}

Tag2Sub3::Tag2Sub3(const std::string & data)
    : Tag2Sub3()
{
    read(data);
}

void Tag2Sub3::read(const std::string & data){
    time = toint(data, 256);
}

std::string Tag2Sub3::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "Signature Expiration Time (Days): " + (time?show_time(time):"Never");
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

#include "Tag2Sub3.h"

Tag2Sub3::Tag2Sub3()
    : Tag2Subpacket(Tag2Subpacket::SIGNATURE_EXPIRATION_TIME, 4),
      dt(0)
{}

Tag2Sub3::Tag2Sub3(const std::string & data)
    : Tag2Sub3()
{
    read(data);
}

void Tag2Sub3::read(const std::string & data){
    dt = toint(data, 256);
}

std::string Tag2Sub3::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "Signature Expiration Time (Days): " + (dt?show_time(dt):"Never");
}

std::string Tag2Sub3::raw() const{
    return unhexlify(makehex(dt, 8));
}

uint32_t Tag2Sub3::get_dt() const{
    return dt;
}

void Tag2Sub3::set_dt(const uint32_t t){
    dt = t;
}

Tag2Subpacket::Ptr Tag2Sub3::clone() const{
    return std::make_shared <Tag2Sub3> (*this);
}

#include "Tag2Sub9.h"

Tag2Sub9::Tag2Sub9()
    : Tag2Subpacket(Tag2Subpacket::KEY_EXPIRATION_TIME, 4),
      dt()
{}

Tag2Sub9::Tag2Sub9(const std::string & data)
    : Tag2Sub9()
{
    read(data);
}

void Tag2Sub9::read(const std::string & data){
    dt = static_cast <time_t> (toint(data, 256));
}
std::string Tag2Sub9::show(const time_t create_time, const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');

    std::string out = indent + show_title() + "\n" +
                      indent + tab + "Key Expiration Time: ";
    if (dt == 0){
        out += "Never";
    }
    else{
        out += show_time(create_time + dt);
    }

    return out;
}

std::string Tag2Sub9::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');

    std::string out = indent + show_title() + "\n" +
                      indent + tab + "Key Expiration Time: ";

    if (dt == 0){
        out += "Never";
    }
    else{
        out += show_dt(dt) + " after key creation";
    }

    return out;
}

std::string Tag2Sub9::raw() const{
    return unhexlify(makehex(dt, 8));
}

time_t Tag2Sub9::get_dt() const{
    return dt;
}

void Tag2Sub9::set_dt(const time_t t){
    dt = t;
}

Tag2Subpacket::Ptr Tag2Sub9::clone() const{
    return std::make_shared <Tag2Sub9> (*this);
}

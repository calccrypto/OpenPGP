#include "Sub9.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub9::Sub9()
    : Sub(KEY_EXPIRATION_TIME, 4),
      dt()
{}

Sub9::Sub9(const std::string & data)
    : Sub9()
{
    read(data);
}

void Sub9::read(const std::string & data){
    dt = static_cast <uint32_t> (toint(data, 256));
}

std::string Sub9::show(const uint32_t create_time, const std::size_t indents, const std::size_t indent_size) const{
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

std::string Sub9::show(const std::size_t indents, const std::size_t indent_size) const{
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

std::string Sub9::raw() const{
    return unhexlify(makehex(dt, 8));
}

uint32_t Sub9::get_dt() const{
    return dt;
}

void Sub9::set_dt(const uint32_t t){
    dt = t;
}

Sub::Ptr Sub9::clone() const{
    return std::make_shared <Sub9> (*this);
}

}
}
}
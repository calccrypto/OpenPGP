#include "Sub3.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub3::Sub3()
    : Sub(SIGNATURE_EXPIRATION_TIME, 4),
      dt(0)
{}

Sub3::Sub3(const std::string & data)
    : Sub3()
{
    read(data);
}

void Sub3::read(const std::string & data){
    dt = toint(data, 256);
}

std::string Sub3::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "Signature Expiration Time (Days): " + (dt?show_time(dt):"Never");
}

std::string Sub3::raw() const{
    return unhexlify(makehex(dt, 8));
}

uint32_t Sub3::get_dt() const{
    return dt;
}

void Sub3::set_dt(const uint32_t t){
    dt = t;
}

Sub::Ptr Sub3::clone() const{
    return std::make_shared <Sub3> (*this);
}

}
}
}
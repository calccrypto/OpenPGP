#include "Sub2.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub2::Sub2()
    : Sub(SIGNATURE_CREATION_TIME, 4),
      time()
{}

Sub2::Sub2(const std::string & data)
    : Sub2()
{
    read(data);
}

void Sub2::read(const std::string & data){
    time = toint(data, 256);
}

std::string Sub2::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "Creation Time: " + show_time(time);
}

std::string Sub2::raw() const{
    return unhexlify(makehex(static_cast <uint32_t> (time), 8));
}

uint32_t Sub2::get_time() const{
    return time;
}

void Sub2::set_time(const uint32_t t){
    time = t;
}

Sub::Ptr Sub2::clone() const{
    return std::make_shared <Sub2> (*this);
}

}
}
}
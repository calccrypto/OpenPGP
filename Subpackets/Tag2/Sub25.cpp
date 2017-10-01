#include "Sub25.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub25::Sub25()
    : Sub(PRIMARY_USER_ID, 1),
      primary()
{}

Sub25::Sub25(const std::string & data)
    : Sub25()
{
    read(data);
}

void Sub25::read(const std::string & data){
    if (data.size()){
        primary = data[0];
    }
}

std::string Sub25::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "Primary: " + + (primary?"True":"False");
}

std::string Sub25::raw() const{
    return (primary?"\x01":zero);
}

bool Sub25::get_primary() const{
    return primary;
}

void Sub25::set_primary(const bool p){
    primary = p;
}

Sub::Ptr Sub25::clone() const{
    return std::make_shared <Sub25> (*this);
}

}
}
}
#include "Sub10.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub10::Sub10()
    : Sub(PLACEHOLDER_FOR_BACKWARD_COMPATIBILITY),
      stuff()
{}

Sub10::Sub10(const std::string & data)
    : Sub10()
{
    read(data);
}

void Sub10::read(const std::string & data){
    stuff = data;
    size = data.size();
}

std::string Sub10::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + stuff;
}

std::string Sub10::raw() const{
    return stuff;
}

std::string Sub10::get_stuff() const{
    return stuff;
}

void Sub10::set_stuff(const std::string & s){
    stuff = s;
}

Sub::Ptr Sub10::clone() const{
    return std::make_shared <Sub10> (*this);
}

}
}
}
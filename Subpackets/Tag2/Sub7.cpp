#include "Sub7.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub7::Sub7()
    : Sub(REVOCABLE, 1),
      revocable()
{}

Sub7::Sub7(const std::string & data)
    : Sub7()
{
    read(data);
}

void Sub7::read(const std::string & data){
    if (data.size()){
        revocable = data[0];
    }
}

std::string Sub7::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "Revocable: " + (revocable?"True":"False");
}

std::string Sub7::raw() const{
    return (revocable?"\x01":zero);
}

bool Sub7::get_revocable() const{
    return revocable;
}

void Sub7::set_revocable(const bool r){
    revocable = r;
}

Sub::Ptr Sub7::clone() const{
    return std::make_shared <Sub7> (*this);
}

}
}
}
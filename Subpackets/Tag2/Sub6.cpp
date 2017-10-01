#include "Sub6.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub6::Sub6()
    : Sub(REGULAR_EXPRESSION),
      regex()
{}

Sub6::Sub6(const std::string & data)
    : Sub6()
{
    read(data);
}

void Sub6::read(const std::string & data){
    regex = data;
    size = data.size();
}

std::string Sub6::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "Regular Expression: " + regex;
}

std::string Sub6::raw() const{
    return regex + zero; // might not need '+ zero'
}

std::string Sub6::get_regex() const{
    return regex;
}

void Sub6::set_regex(const std::string & r){
    regex = r;
}

Sub::Ptr Sub6::clone() const{
    return std::make_shared <Sub6> (*this);
}

}
}
}
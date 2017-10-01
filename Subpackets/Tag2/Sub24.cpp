#include "Sub24.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub24::Sub24()
    : Sub(PREFERRED_KEY_SERVER),
      pks()
{}

Sub24::Sub24(const std::string & data)
    : Sub24()
{
    read(data);
}

void Sub24::read(const std::string & data){
    pks = data;
    size = data.size();
}

std::string Sub24::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "URI - " + pks;
}

std::string Sub24::raw() const{
    return pks;
}

std::string Sub24::get_pks() const{
    return pks;
}

void Sub24::set_pks(const std::string & p){
    pks = p;
}

Sub::Ptr Sub24::clone() const{
    return std::make_shared <Sub24> (*this);
}

}
}
}
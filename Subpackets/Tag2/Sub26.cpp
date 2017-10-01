#include "Sub26.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub26::Sub26()
    : Sub(POLICY_URI),
      uri()
{}

Sub26::Sub26(const std::string & data)
    : Sub26()
{
    read(data);
}

void Sub26::read(const std::string & data){
    uri = data;
    size = data.size();
}

std::string Sub26::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "Policy - " + uri;
}

std::string Sub26::raw() const{
    return uri;
}

std::string Sub26::get_uri() const{
    return uri;
}

void Sub26::set_uri(const std::string & u){
    uri = u;
}

Sub::Ptr Sub26::clone() const{
    return std::make_shared <Sub26> (*this);
}

}
}
}
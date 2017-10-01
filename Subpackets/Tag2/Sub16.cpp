#include "Sub16.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub16::Sub16()
    : Sub(ISSUER, 8),
      keyid()
{}

Sub16::Sub16(const std::string & data)
    : Sub16()
{
    read(data);
}

void Sub16::read(const std::string & data){
    keyid = data;
}

std::string Sub16::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "Key ID: " + hexlify(keyid);
}

std::string Sub16::raw() const{
    return keyid;
}

std::string Sub16::get_keyid() const{
    return keyid;
}

void Sub16::set_keyid(const std::string & k){
    if (k.size() != 8){
        throw std::runtime_error("Error: Key ID must be 8 octets.");
    }
    keyid = k;
}

Sub::Ptr Sub16::clone() const{
    return std::make_shared <Sub16> (*this);
}

}
}
}
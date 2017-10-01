#include "Sub28.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub28::Sub28()
    : Sub(SIGNERS_USER_ID, 0),
      signer()
{}

Sub28::Sub28(const std::string & data)
    : Sub28()
{
    read(data);
}

void Sub28::read(const std::string & data){
    signer = data;
    size = data.size();
}

std::string Sub28::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "ID: " + signer;
}

std::string Sub28::raw() const{
    return signer;
}

std::string Sub28::get_signer() const{
    return signer;
}

void Sub28::set_signer(const std::string & s){
    size = s.size();
    signer = s;
}

Sub::Ptr Sub28::clone() const{
    return std::make_shared <Sub28> (*this);
}

}
}
}
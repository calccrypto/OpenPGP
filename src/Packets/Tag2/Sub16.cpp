#include "Packets/Tag2/Sub16.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub16::actual_read(const std::string & data){
    set_keyid(data);
}

void Sub16::show_contents(HumanReadable & hr) const{
    hr << "Key ID: " + hexlify(keyid);
}

Sub16::Sub16()
    : Sub(ISSUER, 8),
      keyid()
{}

Sub16::Sub16(const std::string & data)
    : Sub16()
{
    read(data);
}

std::string Sub16::raw() const{
    return keyid;
}

std::string Sub16::get_keyid() const{
    return keyid;
}

void Sub16::set_keyid(const std::string & k){
    keyid = k;
}

Sub::Ptr Sub16::clone() const{
    return std::make_shared <Sub16> (*this);
}

}
}
}

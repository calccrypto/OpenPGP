#include "Packets/Tag2/Sub28.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub28::actual_read(const std::string & data){
    set_signer(data);
}

void Sub28::show_contents(HumanReadable & hr) const{
    hr << "ID: " + signer;
}

Sub28::Sub28()
    : Sub(SIGNERS_USER_ID, 0),
      signer()
{}

Sub28::Sub28(const std::string & data)
    : Sub28()
{
    read(data);
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

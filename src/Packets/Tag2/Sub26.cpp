#include "Packets/Tag2/Sub26.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub26::actual_read(const std::string & data){
    set_uri(data);
}

void Sub26::show_contents(HumanReadable & hr) const{
    hr << "Policy - " + uri;
}

Sub26::Sub26()
    : Sub(POLICY_URI),
      uri()
{}

Sub26::Sub26(const std::string & data)
    : Sub26()
{
    read(data);
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

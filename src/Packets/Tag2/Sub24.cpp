#include "Packets/Tag2/Sub24.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub24::actual_read(const std::string & data){
    set_pks(data);
}

void Sub24::show_contents(HumanReadable & hr) const{
    hr << "URI - " + pks;
}

Sub24::Sub24()
    : Sub(PREFERRED_KEY_SERVER),
      pks()
{}

Sub24::Sub24(const std::string & data)
    : Sub24()
{
    read(data);
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

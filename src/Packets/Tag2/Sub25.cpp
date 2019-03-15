#include "Packets/Tag2/Sub25.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub25::actual_read(const std::string & data){
    if (data.size()){
        set_primary(data[0]);
    }
}

void Sub25::show_contents(HumanReadable & hr) const{
    hr << std::string("Primary: ") + + (primary?"True":"False");
}

Sub25::Sub25()
    : Sub(PRIMARY_USER_ID, 1),
      primary()
{}

Sub25::Sub25(const std::string & data)
    : Sub25()
{
    read(data);
}

std::string Sub25::raw() const{
    return std::string(1, primary);
}

bool Sub25::get_primary() const{
    return primary;
}

void Sub25::set_primary(const bool p){
    primary = p;
}

Sub::Ptr Sub25::clone() const{
    return std::make_shared <Sub25> (*this);
}

}
}
}

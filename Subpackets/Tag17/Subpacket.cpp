#include "Subpacket.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag17 {

std::string Sub::show_title() const{
    return Subpacket::Sub::show_title() + NAME.at(type) + " Subpacket (sub " + std::to_string(type) + ") (" + std::to_string(size) + " octets)";
}

Sub::~Sub(){}

Sub & Sub::operator=(const Sub & copy){
    Subpacket::Sub::operator=(copy);
    return *this;
}

}
}
}

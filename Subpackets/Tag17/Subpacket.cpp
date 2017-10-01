#include "Subpacket.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag17 {

std::string Base::show_title() const{
    return Base::show_title() + NAME.at(type) + " Subpacket (sub " + std::to_string(type) + ") (" + std::to_string(size) + " octets)";
}

Base::~Base(){}

Base & Base::operator=(const Base & copy){
    Subpacket::Base::operator=(copy);
    return *this;
}

}
}
}
#include "Packets/Tag2/Sub15.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub15::Sub15(...){
    throw std::runtime_error("Error: Reserved Subpacket.");
}

Sub::Ptr Sub15::clone() const{
    return std::make_shared <Sub15> (*this);
}

}
}
}

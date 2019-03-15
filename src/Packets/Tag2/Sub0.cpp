#include "Packets/Tag2/Sub0.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub0::Sub0(...){
    throw std::runtime_error("Error: Reserved Subpacket.");
}

Sub::Ptr Sub0::clone() const{
    return std::make_shared <Sub0> (*this);
}

}
}
}

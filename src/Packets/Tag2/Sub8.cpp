#include "Packets/Tag2/Sub8.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub8::Sub8(...) {
    throw std::runtime_error("Error: Reserved Subpacket.");
}

Sub::Ptr Sub8::clone() const {
    return std::make_shared <Sub8> (*this);
}

}
}
}

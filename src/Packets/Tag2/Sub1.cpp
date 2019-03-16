#include "Packets/Tag2/Sub1.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub1::Sub1(...) {
    throw std::runtime_error("Error: Reserved Subpacket.");
}

Sub::Ptr Sub1::clone() const {
    return std::make_shared <Sub1> (*this);
}

}
}
}

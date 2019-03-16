#include "Packets/Tag2/Sub18.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub18::Sub18(...) {
    throw std::runtime_error("Error: Reserved Subpacket.");
}

Sub::Ptr Sub18::clone() const {
    return std::make_shared <Sub18> (*this);
}

}
}
}

#include "Packets/Tag2/Sub13.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub13::Sub13(...) {
    throw std::runtime_error("Error: Reserved Subpacket.");
}

Sub::Ptr Sub13::clone() const {
    return std::make_shared <Sub13> (*this);
}

}
}
}

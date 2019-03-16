#include "Packets/Tag2/Sub17.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub17::Sub17(...) {
    throw std::runtime_error("Error: Reserved Subpacket.");
}

Sub::Ptr Sub17::clone() const {
    return std::make_shared <Sub17> (*this);
}

}
}
}

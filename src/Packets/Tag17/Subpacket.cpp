#include "Packets/Tag17/Subpacket.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag17 {

std::string Sub::show_type() const {
    return NAME.at(type) + " Subpacket (sub " + std::to_string(type) + ") (" + std::to_string(size) + " octets)";
}

Sub::Sub(uint8_t type, unsigned int size, bool crit)
    : Subpacket::Sub(type, size, crit)
{}

Sub::~Sub() {}

}
}
}

#include "Packets/Tag2/Subpacket.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub::actual_read(const std::string &) {}

std::string Sub::show_type() const {
    return NAME.at(type) + " Subpacket (sub " + std::to_string(type) + ") (" + std::to_string(size) + " octets)";
}

void Sub::show_contents(HumanReadable &) const {}

Sub::Sub(uint8_t type, unsigned int size, bool crit)
    : Subpacket::Sub(type, size, crit)
{}

Sub::~Sub() {}

}
}
}

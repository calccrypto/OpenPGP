#include "Packets/Tag2/Sub23.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub23::actual_read(const std::string & data) {
    set_flags(data);
}

void Sub23::show_contents(HumanReadable & hr) const {
    for(char const octet : flags) {
        for(uint8_t bit = 0; bit < 8; bit++) {
            const uint8_t mask = 1U << bit;
            if (octet & mask) {
                hr << "Flag - " + get_mapped(Key_Server_Preferences::NAME, mask) + " (key 0x" + makehex(mask, 2) + ")";
            }
        }
    }
}

Status Sub23::actual_valid(const bool) const {
    for(char const octet : flags) {
        for(uint8_t bit = 0; bit < 8; bit++) {
            const uint8_t mask = 1U << bit;
            if (octet & mask) {
                if (Key_Server_Preferences::NAME.find(mask) == Key_Server_Preferences::NAME.end()) {
                    return Status::INVALID_FLAG;
                }
            }
        }
    }
    return Status::SUCCESS;
}

Sub23::Sub23()
    : Sub(KEY_SERVER_PREFERENCES),
      flags()
{}

Sub23::Sub23(const std::string & data)
    : Sub23()
{
    read(data);
}

std::string Sub23::raw() const {
    return flags;
}

std::string Sub23::get_flags() const {
    return flags;
}

void Sub23::set_flags(const std::string & f) {
    flags = f;
}

Sub::Ptr Sub23::clone() const {
    return std::make_shared <Sub23> (*this);
}

}
}
}

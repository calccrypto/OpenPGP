#include "Packets/Tag2/Sub5.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub5::actual_read(const std::string & data) {
    if (data.size() >= 2) {
        set_level(data[0]);
        set_amount(data[1]);
    }
}

void Sub5::show_contents(HumanReadable & hr) const {
    hr << "Trust Level: " + std::to_string(level)
       << "Trust Amount: " + std::to_string(amount);
}

Sub5::Sub5()
    : Sub(TRUST_SIGNATURE, 2),
      level(),
      amount()
{}

Sub5::Sub5(const std::string & data)
    : Sub5()
{
    read(data);
}

std::string Sub5::raw() const {
    return std::string(1, level) + std::string(1, amount);
}

uint8_t Sub5::get_level() const {
    return level;
}

uint8_t Sub5::get_amount() const {
    return amount;
}

void Sub5::set_level(const uint8_t l) {
    level = l;
}

void Sub5::set_amount(const uint8_t a) {
    amount = a;
}

Sub::Ptr Sub5::clone() const {
    return std::make_shared <Sub5> (*this);
}

}
}
}

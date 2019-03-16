#include "Packets/Tag2/Sub10.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub10::actual_read(const std::string & data) {
    set_stuff(data);
}

void Sub10::show_contents(HumanReadable & hr) const {
    hr << stuff;
}

Sub10::Sub10()
    : Sub(PLACEHOLDER_FOR_BACKWARD_COMPATIBILITY),
      stuff()
{}

Sub10::Sub10(const std::string & data)
    : Sub10()
{
    read(data);
}

std::string Sub10::raw() const {
    return stuff;
}

std::string Sub10::get_stuff() const {
    return stuff;
}

void Sub10::set_stuff(const std::string & s) {
    stuff = s;
}

Sub::Ptr Sub10::clone() const {
    return std::make_shared <Sub10> (*this);
}

}
}
}

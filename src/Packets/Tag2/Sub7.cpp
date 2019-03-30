#include "Packets/Tag2/Sub7.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub7::actual_read(const std::string & data) {
    if (data.size()) {
        set_revocable(data[0]);
    }
}

void Sub7::show_contents(HumanReadable & hr) const {
    hr << std::string("Revocable: ") + (revocable?"True":"False");
}

Status Sub7::actual_valid(const bool) const {
    return Status::SUCCESS;
}

Sub7::Sub7()
    : Sub(REVOCABLE, 1),
      revocable()
{}

Sub7::Sub7(const std::string & data)
    : Sub7()
{
    read(data);
}

std::string Sub7::raw() const {
    return std::string(1, revocable);
}

bool Sub7::get_revocable() const {
    return revocable;
}

void Sub7::set_revocable(const bool r) {
    revocable = r;
}

Sub::Ptr Sub7::clone() const {
    return std::make_shared <Sub7> (*this);
}

}
}
}

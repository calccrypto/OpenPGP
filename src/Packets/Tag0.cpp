#include "Packets/Tag0.h"

#include <stdexcept>

namespace OpenPGP {
namespace Packet {

void Tag0::actual_read(const std::string &, std::string::size_type &, const std::string::size_type &) {}

void Tag0::show_contents(HumanReadable &) const {}

std::string Tag0::actual_raw() const {
    return "";
}

Status Tag0::actual_valid(const bool) const {
    return Status::INVALID_TAG;
}

Tag0::Tag0(...)
    : Tag(RESERVED)
{
    throw std::runtime_error("Error: Tag number MUST NOT be 0.");
}

Tag::Ptr Tag0::clone() const {
    return std::make_shared <Tag0> (*this);
}

}
}

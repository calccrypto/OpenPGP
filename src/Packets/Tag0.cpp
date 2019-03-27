#include "Packets/Tag0.h"

#include <stdexcept>

namespace OpenPGP {
namespace Packet {

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

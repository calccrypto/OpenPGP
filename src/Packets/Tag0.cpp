#include "Packets/Tag0.h"

#include <stdexcept>

namespace OpenPGP {
namespace Packet {

void Tag0::actual_read(const std::string &){}

Tag0::Tag0(...)
    : Tag(RESERVED)
{
    throw std::runtime_error("Error: Tag number MUST NOT be 0.");
}

std::string Tag0::raw() const{
    return "";
}

Tag::Ptr Tag0::clone() const{
    return std::make_shared <Tag0> (*this);
}

}
}

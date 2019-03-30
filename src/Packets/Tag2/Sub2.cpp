#include "Packets/Tag2/Sub2.h"

#include "Misc/pgptime.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub2::actual_read(const std::string & data) {
    set_time(toint(data, 256));
}

void Sub2::show_contents(HumanReadable & hr) const {
    hr << "Creation Time: " + show_time(timestamp);
}

Status Sub2::actual_valid(const bool) const {
    return Status::SUCCESS;
}

Sub2::Sub2()
    : Sub(SIGNATURE_CREATION_TIME, 4),
      timestamp()
{}

Sub2::Sub2(const std::string & data)
    : Sub2()
{
    read(data);
}

std::string Sub2::raw() const {
    return unhexlify(makehex(static_cast <uint32_t> (timestamp), 8));
}

uint32_t Sub2::get_time() const {
    return timestamp;
}

void Sub2::set_time(const uint32_t t) {
    timestamp = t;
}

Sub::Ptr Sub2::clone() const {
    return std::make_shared <Sub2> (*this);
}

}
}
}

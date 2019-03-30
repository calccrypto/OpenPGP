#include "Packets/Tag2/Sub3.h"

#include "Misc/pgptime.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub3::actual_read(const std::string & data) {
    set_dt(toint(data, 256));
}

void Sub3::show_contents(HumanReadable & hr) const {
    hr << "Signature Expiration Time (Days): " + (dt?show_time(dt):"Never");
}

Status Sub3::actual_valid(const bool) const {
    return Status::SUCCESS;
}

Sub3::Sub3()
    : Sub(SIGNATURE_EXPIRATION_TIME, 4),
      dt(0)
{}

Sub3::Sub3(const std::string & data)
    : Sub3()
{
    read(data);
}

std::string Sub3::raw() const {
    return unhexlify(makehex(dt, 8));
}

uint32_t Sub3::get_dt() const {
    return dt;
}

void Sub3::set_dt(const uint32_t t) {
    dt = t;
}

Sub::Ptr Sub3::clone() const {
    return std::make_shared <Sub3> (*this);
}

}
}
}

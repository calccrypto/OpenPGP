#include "Packets/Tag2/Sub9.h"

#include "Misc/pgptime.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub9::actual_read(const std::string & data) {
    set_dt(static_cast <uint32_t> (toint(data, 256)));
}

void Sub9::show_contents(HumanReadable & hr) const {
    hr << "Key Expiration Time: " + (dt?(show_dt(dt) + " after key creation"):"Never");
}

Status Sub9::actual_valid(const bool) const {
    return Status::SUCCESS;
}

Sub9::Sub9()
    : Sub(KEY_EXPIRATION_TIME, 4),
      dt()
{}

Sub9::Sub9(const std::string & data)
    : Sub9()
{
    read(data);
}

void Sub9::show(const uint32_t create_time, HumanReadable & hr) const {
    hr << show_critical() + show_type()
       << HumanReadable::DOWN
       << "Key Expiration Time: " + (dt?show_time(create_time + dt):"Never")
       << HumanReadable::UP;
}

std::string Sub9::raw() const {
    return unhexlify(makehex(dt, 8));
}

uint32_t Sub9::get_dt() const {
    return dt;
}

void Sub9::set_dt(const uint32_t t) {
    dt = t;
}

Sub::Ptr Sub9::clone() const {
    return std::make_shared <Sub9> (*this);
}

}
}
}

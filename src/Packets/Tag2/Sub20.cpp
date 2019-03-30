#include "Packets/Tag2/Sub20.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub20::actual_read(const std::string & data) {
    if (data.size() >= 8) {
        set_flags(data.substr(0, 4));
        const uint16_t mlen = toint(data.substr(4, 2), 256);
        const uint16_t nlen = toint(data.substr(6, 2), 256);
        if (data.size() > (8U + mlen + nlen)) {
            set_m(data.substr(8U, mlen));
            set_n(data.substr(8U + mlen, nlen));
        }
        // size  = 4 + mlen + nlen;
    }
}

void Sub20::show_contents(HumanReadable & hr) const {
    for(char const & f : flags) {
        hr << "Flag - " + get_mapped(Notation::NAME, (uint8_t) f) + " (not " + std::to_string(f) + ")";
    }

    hr << "Name: " + m;
    hr << "Value: " + n;
}

Status Sub20::actual_valid(const bool) const {
    for(char const & f : flags) {
        if (Notation::NAME.find(f) == Notation::NAME.end()) {
            return Status::INVALID_FLAG;
        }
    }
    return Status::SUCCESS;
}

Sub20::Sub20()
    : Sub(NOTATION_DATA),
      flags(),
      m(), n()
{}

Sub20::Sub20(const std::string & data)
    : Sub20()
{
    read(data);
}

std::string Sub20::raw() const {
    return flags + unhexlify(makehex(m.size(), 4)) + unhexlify(makehex(n.size(), 4)) + m + n;
}

std::string Sub20::get_flags() const {
    return flags;
}

std::string Sub20::get_m() const {
    return m;
}

std::string Sub20::get_n() const {
    return n;
}

void Sub20::set_flags(const std::string & f) {
    flags = f;
}

void Sub20::set_m(const std::string & s) {
    m = s;
}

void Sub20::set_n(const std::string & s) {
    n = s;
}

Sub::Ptr Sub20::clone() const {
    return std::make_shared <Sub20> (*this);
}

}
}
}

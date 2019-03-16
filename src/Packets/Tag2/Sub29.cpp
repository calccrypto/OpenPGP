#include "Packets/Tag2/Sub29.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub29::actual_read(const std::string & data) {
    if (data.size()) {
        set_code(data[0]);
        set_reason(data.substr(1, data.size() - 1));
    }
}

void Sub29::show_contents(HumanReadable & hr) const {
    const decltype(Revoke::NAME)::const_iterator revoke_it = Revoke::NAME.find(code);

    hr << std::string("Reason ") + std::to_string(code) + " - " + ((revoke_it == Revoke::NAME.end())?"Unknown":(revoke_it -> second));
    if (code) {
        hr << std::string("Comment - ") + reason;
    }
}

bool Revoke::is_key_revocation(const uint8_t code) {
    return code <= KEY_IS_NO_LONGER_USED;
}

Sub29::Sub29()
    : Sub(REASON_FOR_REVOCATION),
      code(),
      reason()
{}

Sub29::Sub29(const std::string & data)
    : Sub29()
{
    read(data);
}

std::string Sub29::raw() const {
    return std::string(1, code) + reason;
}

uint8_t Sub29::get_code() const {
    return code;
}

std::string Sub29::get_reason() const {
    return reason;
}

void Sub29::set_code(const uint8_t c) {
    code = c;
}

void Sub29::set_reason(const std::string & r) {
    reason = r;
}

Sub::Ptr Sub29::clone() const {
    return std::make_shared <Sub29> (*this);
}

}
}
}

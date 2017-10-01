#include "Sub29.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

bool Revoke::is_key_revocation(const uint8_t code){
    return ((NO_REASON_SPECIFIED <= code) &&
            (code <= KEY_IS_NO_LONGER_USED));
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

void Sub29::read(const std::string & data){
    if (data.size()){
        code = data[0];
        reason = data.substr(1, data.size() - 1);
        size = data.size();
    }
}

std::string Sub29::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');

    const decltype(Revoke::NAME)::const_iterator revoke_it = Revoke::NAME.find(code);

    std::string out = indent + show_title() + "\n" +
                      indent + tab + "Reason " + std::to_string(code) + " - " + ((revoke_it == Revoke::NAME.end())?"Unknown":(revoke_it -> second));
    if (code){
        out += "\n" + indent + tab + "Comment - " + reason;
    }

    return out;
}

std::string Sub29::raw() const{
    return std::string(1, code) + reason;
}

uint8_t Sub29::get_code() const{
    return code;
}

std::string Sub29::get_reason() const{
    return reason;
}

void Sub29::set_code(const uint8_t c){
    code = c;
}

void Sub29::set_reason(const std::string & r){
    reason = r;
}

Sub::Ptr Sub29::clone() const{
    return std::make_shared <Sub29> (*this);
}

}
}
}
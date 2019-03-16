#include "Packets/Tag2/Sub6.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub6::actual_read(const std::string & data) {
    set_regex(data);
}

void Sub6::show_contents(HumanReadable & hr) const {
    hr << "Regular Expression: " + regex;
}

Sub6::Sub6()
    : Sub(REGULAR_EXPRESSION),
      regex()
{}

Sub6::Sub6(const std::string & data)
    : Sub6()
{
    read(data);
}

std::string Sub6::raw() const {
    return regex + zero; // might not need '+ zero'
}

std::string Sub6::get_regex() const {
    return regex;
}

void Sub6::set_regex(const std::string & r) {
    regex = r;

    // remove trailing null characters
    while (regex.size() && !regex.back()) {
        regex.pop_back();
    }
}

Sub::Ptr Sub6::clone() const {
    return std::make_shared <Sub6> (*this);
}

}
}
}

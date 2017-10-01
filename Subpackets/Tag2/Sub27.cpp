#include "Sub27.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub27::Sub27()
    : Sub(KEY_FLAGS),
      flags()
{}

Sub27::Sub27(const std::string & data)
    : Sub27()
{
    read(data);
}

void Sub27::read(const std::string & data){
    flags = data;
    size = data.size();
}

std::string Sub27::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');

    std::string out = indent + show_title();
    for(char const octet : flags){
        for(uint8_t bit = 0; bit < 8; bit++){
            if (octet & (1 << bit)){
                const decltype(Key_Flags::NAME)::const_iterator kf_it = Key_Flags::NAME.find(1 << bit);
                out += "\n" + indent + tab + "Flag - " + ((kf_it == Key_Flags::NAME.end())?"Unknown":(kf_it -> second)) + " (key 0x" + makehex(1 << bit, 2) + ")";
            }
        }
    }

    return out;
}

std::string Sub27::raw() const{
    return flags;
}

std::string Sub27::get_flags() const{
    return flags;
}

void Sub27::set_flags(const std::string & f){
    flags = f;
}

Sub::Ptr Sub27::clone() const{
    return std::make_shared <Sub27> (*this);
}

}
}
}
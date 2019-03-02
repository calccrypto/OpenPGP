#include "Packets/Tag2/Sub27.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub27::actual_read(const std::string & data){
    set_flags(data);
}

void Sub27::show_contents(HumanReadable & hr) const{
    for(char const octet : flags){
        for(uint8_t bit = 0; bit < 8; bit++){
            if (octet & (1 << bit)){
                const decltype(Key_Flags::NAME)::const_iterator kf_it = Key_Flags::NAME.find(1 << bit);
                hr << "Flag - " + ((kf_it == Key_Flags::NAME.end())?"Unknown":(kf_it -> second)) + " (key 0x" + makehex(1 << bit, 2) + ")";
            }
        }
    }
}

Sub27::Sub27()
    : Sub(KEY_FLAGS),
      flags()
{}

Sub27::Sub27(const std::string & data)
    : Sub27()
{
    read(data);
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

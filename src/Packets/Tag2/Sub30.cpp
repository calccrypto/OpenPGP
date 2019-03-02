#include "Packets/Tag2/Sub30.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub30::actual_read(const std::string & data){
    set_flags(data);
}

void Sub30::show_contents(HumanReadable & hr) const{
    for(char const octet : flags){
        for(uint8_t bit = 0; bit < 8; bit++){
            if (octet & (1 << bit)){
                const decltype(Features_Flags::NAME)::const_iterator ff_it = Features_Flags::NAME.find(1 << bit);
                hr << "Flag - " + ((ff_it == Features_Flags::NAME.end())?"Unknown":(ff_it -> second)) + " (feat " + std::to_string(1 << bit) + ")";
            }
        }
    }
}

Sub30::Sub30()
    : Sub(FEATURES),
      flags()
{}

Sub30::Sub30(const std::string & data)
    : Sub30()
{
    read(data);
}

std::string Sub30::raw() const{
    return flags;
}

std::string Sub30::get_flags() const{
    return flags;
}

void Sub30::set_flags(const std::string & f){
    flags = f;
}

Sub::Ptr Sub30::clone() const{
    return std::make_shared <Sub30> (*this);
}

}
}
}

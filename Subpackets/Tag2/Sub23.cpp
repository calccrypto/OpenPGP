#include "Sub23.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub23::Sub23()
    : Sub(KEY_SERVER_PREFERENCES),
      flags()
{}

Sub23::Sub23(const std::string & data)
    : Sub23()
{
    read(data);
}

void Sub23::read(const std::string & data){
    flags = data;
    size = data.size();
}

std::string Sub23::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');

    std::string out = indent + show_title();
    for(char const octet : flags){
        for(uint8_t bit = 0; bit < 8; bit++){
            if (octet & (1 << bit)){
                const decltype(Key_Server_Preferences::NAME)::const_iterator ksp_it = Key_Server_Preferences::NAME.find(1 << bit);
                out += "\n" + indent + tab + "Flag - " + ((ksp_it == Key_Server_Preferences::NAME.end())?"Unknown":(ksp_it -> second)) + " (key 0x" + makehex(1 << bit, 2) + ")";
            }
        }
    }

    return out;
}

std::string Sub23::raw() const{
    return flags;
}

std::string Sub23::get_flags() const{
    return flags;
}

void Sub23::set_flags(const std::string & f){
    flags = f;
}

Sub::Ptr Sub23::clone() const{
    return std::make_shared <Sub23> (*this);
}

}
}
}
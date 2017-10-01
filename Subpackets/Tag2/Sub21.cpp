#include "Sub21.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub21::Sub21()
    : Sub(PREFERRED_HASH_ALGORITHMS),
      pha()
{}

Sub21::Sub21(const std::string & data)
    : Sub21()
{
    read(data);
}

void Sub21::read(const std::string & data){
    pha = data;
    size = data.size();
}

std::string Sub21::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');

    std::string out = indent + show_title();
    for(char const & c : pha){
        const decltype(Hash::NAME)::const_iterator hash_it = Hash::NAME.find(c);
        out += "\n" + indent + tab + "hash alg - " + ((hash_it == Hash::NAME.end())?"Unknown":(hash_it -> second)) + " (hash " + std::to_string(c) + ")";
    }

    return out;
}

std::string Sub21::raw() const{
    return pha;
}

std::string Sub21::get_pha() const{
    return pha;
}

void Sub21::set_pha(const std::string & p){
    pha = p;
}

Sub::Ptr Sub21::clone() const{
    return std::make_shared <Sub21> (*this);
}

}
}
}
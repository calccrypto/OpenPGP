#include "Tag10.h"

namespace OpenPGP {
namespace Packet {

Tag10::Tag10()
    : Tag(MARKER_PACKET),
      pgp("PGP")
{}

Tag10::Tag10(const Tag10 & copy)
    : Tag(copy),
      pgp(copy.pgp)
{}

Tag10::Tag10(const std::string & data)
    : Tag10()
{
    read(data);
}

void Tag10::read(const std::string & data){
    size = data.size();
    if (data != "PGP"){
        throw std::runtime_error("Error: Tag 10 packet did not contain data \"PGP\".");
    }
}

std::string Tag10::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" + 
           indent + tab + "PGP";
}

std::string Tag10::raw() const{
    return "PGP";
}

std::string Tag10::get_pgp() const{
    return pgp;
}

void Tag10::set_pgp(const std::string & s){
    if (s != "PGP"){
        throw std::runtime_error("Error: Tag 10 input data not string \x5cPGP\x5c.");
    }
    pgp = s;
    size = 3;
}

Tag::Ptr Tag10::clone() const{
    return std::make_shared <Packet::Tag10> (*this);
}

}
}
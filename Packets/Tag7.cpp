#include "Tag7.h"

namespace OpenPGP {
namespace Packet {

Tag7::Tag7()
    : Tag5(SECRET_SUBKEY)
{}

Tag7::Tag7(const Tag7 & copy)
    : Tag5(copy)
{}

Tag7::Tag7(const std::string & data)
    : Tag7()
{
    read(data);
}

Tag7::~Tag7(){}

Tag14 Tag7::get_public_obj() const{
    Tag14 out(raw());
    out.set_tag(PUBLIC_SUBKEY);
    return out;
}

Tag14::Ptr Tag7::get_public_ptr() const{
    Tag14::Ptr out = std::make_shared <Packet::Tag14> (raw());
    out -> set_tag(PUBLIC_SUBKEY);
    return out;
}

Tag::Ptr Tag7::clone() const{
    Ptr out = std::make_shared <Packet::Tag7> (*this);
    out -> s2k = s2k?s2k -> clone():nullptr;
    return out;
}

Tag7 & Tag7::operator=(const Tag7 & copy){
    Tag5::operator=(copy);
    return *this;
}

}
}
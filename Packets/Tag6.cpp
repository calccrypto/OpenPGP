#include "Tag6.h"

namespace OpenPGP {
namespace Packet {

Tag6::Tag6(uint8_t tag)
    : Key(tag)
{}

Tag6::Tag6()
    : Tag6(PUBLIC_KEY)
{}

Tag6::Tag6(const Tag6 & copy)
    : Key(copy)
{}

Tag6::Tag6(const std::string & data)
    : Tag6(PUBLIC_KEY)
{
    read(data);
}

Tag6::~Tag6(){}

Tag::Ptr Tag6::clone() const{
    return std::make_shared <Packet::Tag6> (*this);
}

Tag6 & Tag6::operator=(const Tag6 & copy){
    Key::operator=(copy);
    return *this;
}

}
}
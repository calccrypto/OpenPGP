#include "Tag14.h"

namespace OpenPGP {
namespace Packet {

Tag14::Tag14()
    : Tag6(PUBLIC_SUBKEY)
{}

Tag14::Tag14(const Tag14 & copy)
    : Tag6(copy)
{}

Tag14::Tag14(const std::string & data){
    read(data);
}

Tag14::~Tag14(){}

Tag::Ptr Tag14::clone() const{
    return std::make_shared <Packet::Tag14> (*this);
}

}
}
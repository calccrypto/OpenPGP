#include "Tag14.h"

Tag14::Tag14()
    : Tag6(Packet::ID::Public_Subkey)
{}

Tag14::Tag14(const Tag14 & copy)
    : Tag6(copy)
{}

Tag14::Tag14(const std::string & data){
    read(data);
}

Tag14::~Tag14(){}

Packet::Ptr Tag14::clone() const{
    return std::make_shared <Tag14> (*this);
}

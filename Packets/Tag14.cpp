#include "Tag14.h"

Tag14::Tag14():
    Tag6(14)
{}

Tag14::Tag14(std::string & data){
    read(data);
}

Packet::Ptr Tag14::clone() const{
    return std::make_shared <Tag14> (*this);
}

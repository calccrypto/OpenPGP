#include "Tag6.h"
Tag6::Tag6(uint8_t tag):
    Key(tag)
{}

Tag6::Tag6():
    Tag6(6)
{}

Tag6::Tag6(const Tag6 & copy):
    Key(copy)
{}

Tag6::Tag6(std::string & data):
    Tag6(6)
{
    read(data);
}

Tag6::~Tag6(){}

Packet::Ptr Tag6::clone() const{
    return std::make_shared <Tag6> (*this);
}

Tag6 & Tag6::operator=(const Tag6 & copy){
    Key::operator=(copy);
    return *this;
}

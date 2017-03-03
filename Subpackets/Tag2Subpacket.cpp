#include "Tag2Subpacket.h"

Tag2Subpacket::~Tag2Subpacket(){}

Tag2Subpacket & Tag2Subpacket::operator=(const Tag2Subpacket & copy){
    Subpacket::operator=(copy);
    return *this;
}
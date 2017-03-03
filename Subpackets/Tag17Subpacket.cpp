#include "Tag17Subpacket.h"

Tag17Subpacket::~Tag17Subpacket(){}

Tag17Subpacket & Tag17Subpacket::operator=(const Tag17Subpacket & copy){
    Subpacket::operator=(copy);
    return *this;
}
#include "Tag17Subpacket.h"

const uint8_t Tag17Subpacket::IMAGE_ATTRIBUTE = 1;

const std::map <uint8_t, std::string> Tag17Subpacket::NAME = {
    std::make_pair(Tag17Subpacket::IMAGE_ATTRIBUTE, "Image Attribite"),
};

std::string Tag17Subpacket::show_title() const{
    return Tag17Subpacket::NAME.at(type) + " Subpacket (sub " + std::to_string(type) + ") (" + std::to_string(size) + " octets)";
}

Tag17Subpacket::~Tag17Subpacket(){}

Tag17Subpacket & Tag17Subpacket::operator=(const Tag17Subpacket & copy){
    Subpacket::operator=(copy);
    return *this;
}
#include "Tag17Subpacket.h"

const uint8_t Tag17Subpacket::ID::Image_Attribute = 1;

const std::map <uint8_t, std::string> Tag17Subpacket::Name = {
    std::make_pair(Tag17Subpacket::ID::Image_Attribute, "Image Attribite"),
};

std::string Tag17Subpacket::show_title() const{
    return Tag17Subpacket::Name.at(type) + " Subpacket (sub " + std::to_string(type) + ") (" + std::to_string(size) + " octets)";
}

Tag17Subpacket::~Tag17Subpacket(){}

Tag17Subpacket & Tag17Subpacket::operator=(const Tag17Subpacket & copy){
    Subpacket::operator=(copy);
    return *this;
}
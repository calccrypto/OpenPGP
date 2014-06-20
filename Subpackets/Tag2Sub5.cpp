#include "Tag2Sub5.h"

Tag2Sub5::Tag2Sub5() :
    Subpacket(5, 2),
    level(),
    amount()
{
}

Tag2Sub5::Tag2Sub5(std::string & data) :
    Tag2Sub5()
{
    read(data);
}

void Tag2Sub5::read(std::string & data){
    level = data[0];
    amount = data[1];
}

std::string Tag2Sub5::show(){
    std::stringstream out;
    out << "            Trust Level: " << (unsigned int) level << "\n"
        << "            Trust Amount: " << (unsigned int) amount << "\n";
    return out.str();
}

std::string Tag2Sub5::raw(){
    return std::string(1, level) + std::string(1, amount);
}

uint8_t Tag2Sub5::get_level(){
    return level;
}

uint8_t Tag2Sub5::get_amount(){
    return amount;
}

void Tag2Sub5::set_level(const uint8_t l){
    level = l;
}

void Tag2Sub5::set_amount(const uint8_t a){
    amount = a;
}

Subpacket::Ptr Tag2Sub5::clone() const{
    return Ptr(new Tag2Sub5(*this));
}

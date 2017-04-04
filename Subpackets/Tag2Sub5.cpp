#include "Tag2Sub5.h"

Tag2Sub5::Tag2Sub5()
    : Tag2Subpacket(Tag2Subpacket::TRUST_SIGNATURE, 2),
      level(),
      amount()
{}

Tag2Sub5::Tag2Sub5(const std::string & data)
    : Tag2Sub5()
{
    read(data);
}

void Tag2Sub5::read(const std::string & data){
    level = data[0];
    amount = data[1];
}

std::string Tag2Sub5::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "Trust Level: " + std::to_string(level) + "\n" +
           indent + tab + "Trust Amount: " + std::to_string(amount);
}

std::string Tag2Sub5::raw() const{
    return std::string(1, level) + std::string(1, amount);
}

uint8_t Tag2Sub5::get_level() const{
    return level;
}

uint8_t Tag2Sub5::get_amount() const{
    return amount;
}

void Tag2Sub5::set_level(const uint8_t l){
    level = l;
}

void Tag2Sub5::set_amount(const uint8_t a){
    amount = a;
}

Tag2Subpacket::Ptr Tag2Sub5::clone() const{
    return std::make_shared <Tag2Sub5> (*this);
}

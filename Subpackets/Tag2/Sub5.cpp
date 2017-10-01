#include "Sub5.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub5::Sub5()
    : Sub(TRUST_SIGNATURE, 2),
      level(),
      amount()
{}

Sub5::Sub5(const std::string & data)
    : Sub5()
{
    read(data);
}

void Sub5::read(const std::string & data){
    if (data.size()){
        level = data[0];
        amount = data[1];
    }
}

std::string Sub5::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "Trust Level: " + std::to_string(level) + "\n" +
           indent + tab + "Trust Amount: " + std::to_string(amount);
}

std::string Sub5::raw() const{
    return std::string(1, level) + std::string(1, amount);
}

uint8_t Sub5::get_level() const{
    return level;
}

uint8_t Sub5::get_amount() const{
    return amount;
}

void Sub5::set_level(const uint8_t l){
    level = l;
}

void Sub5::set_amount(const uint8_t a){
    amount = a;
}

Sub::Ptr Sub5::clone() const{
    return std::make_shared <Sub5> (*this);
}

}
}
}
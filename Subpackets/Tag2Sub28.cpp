#include "Tag2Sub28.h"

Tag2Sub28::Tag2Sub28() :
    Subpacket(28, 0),
    signer()
{
}

Tag2Sub28::Tag2Sub28(std::string & data) :
    Tag2Sub28()
{
    read(data);
}

void Tag2Sub28::read(std::string & data){
    signer = data;
    size = data.size();
}

std::string Tag2Sub28::show(){
    return "            ID: " + signer + "\n";
}

std::string Tag2Sub28::raw(){
    return signer;
}

std::string Tag2Sub28::get_signer(){
    return signer;
}

void Tag2Sub28::set_signer(const std::string & s){
    size = s.size();
    signer = s;
}

Subpacket::Ptr Tag2Sub28::clone() const{
    return Ptr(new Tag2Sub28(*this));
}

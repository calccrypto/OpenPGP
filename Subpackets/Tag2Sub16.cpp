#include "Tag2Sub16.h"
Tag2Sub16::Tag2Sub16(){
    type = 16;
    size = 8;
}

Tag2Sub16::Tag2Sub16(std::string & data){
    type = 16;
    size = 8;
    read(data);
}

void Tag2Sub16::read(std::string & data){
    keyid = data;
}

std::string Tag2Sub16::show(){
    return "            Key ID: " + hexlify(keyid) + "\n";
}

std::string Tag2Sub16::raw(){
    return keyid;
}

std::string Tag2Sub16::get_keyid(){
    return keyid;
}

void Tag2Sub16::set_keyid(const std::string & k){
    if (k.size() != 8){
        std::cerr << "Error: Key ID must be 8 octets." << std::endl;
        throw(1);
    }
    keyid = k;
}

Tag2Sub16 * Tag2Sub16::clone(){
    return new Tag2Sub16(*this);
}

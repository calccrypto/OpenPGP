#include "subpacket.h"

std::string Subpacket::write_subpacket(const std::string & data){
    if (data.size() < 192){
        return std::string(1, data.size()) + data;
    }
    else if ((192 <= data.size()) && (data.size() < 8383)){
        return unhexlify(makehex(((((data.size() >> 8) + 192) << 8) + (data.size() & 0xff) - 192), 4)) + data;
    }
    else{
        return "\xff" + unhexlify(makehex(data.size(), 8)) + data;
    }
    return ""; // should never reach here; mainly just to remove compiler warnings
}

Subpacket::~Subpacket(){}

std::string Subpacket::write(){
    return write_subpacket(std::string(1, type) + raw());
}

uint8_t Subpacket::get_type(){
    return type;
}

unsigned int Subpacket::get_size(){
    return size;
}

void Subpacket::set_type(uint8_t t){
    type = t;
}

void Subpacket::set_size(unsigned int s){
    size = s;
}

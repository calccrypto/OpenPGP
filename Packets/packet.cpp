#include "packet.h"
std::string Packet::write_old_length(std::string data){
    unsigned int length = data.size();
    std::string out(1, 0b10000000 | (tag << 2));
    if (length < 256){
        out[0] |= 0;                                                       // 1 octet
        out += std::string(1, length);
    }
    if ((256 <= length) && (length < 65536)){
        out[0] |= 1;
        out += unhexlify(makehex(length, 4));
    }
    if (65536 <= length){
        out[0] |= 2;                                                       // 4 octets
        out += unhexlify(makehex(length, 8));
    }
    else{
        out[0] |= 3;
    }
    return out + data;
}

// returns formatted length string
std::string Packet::write_new_length(std::string data){
    std::string out(1, 0b11000000 | tag);
    unsigned int length = data.size();
    if (length < 192){
        out += std::string(1, length);
    }
    else if ((192 <= length) && (length < 8383)){
        length -= 0xc0;
        out += std::string(1, (length >> 8) + 0xc0 ) + std::string(1, length & 0xff);
    }
    else if (length > 8383){
        out += std::string(1, '\xff') + unhexlify(makehex(length, 8));
    }
//    // partial body length
//    uint8_t add = 0;
//    while (!(length & 1)){
//        add++;
//        length >>= 1;
//    }
//    out += unhexlify(makehex(224 + add, 2));
    return out + data;
}

Packet::~Packet(){}

std::string Packet::write(bool header){
    if (!header && (tag < 16)){
        return write_old_length(raw());
    }
    return write_new_length(raw());
}

uint8_t Packet::get_tag(){
    return tag;
}

bool Packet::get_format(){
    return format;
}

unsigned int Packet::get_version(){
    return version;
}

unsigned int Packet::get_size(){
    return size;
}

void Packet::set_tag(uint8_t t){
    tag = t;
}

void Packet::set_format(bool f){
    format = f;
}

void Packet::set_version(unsigned int v){
    version = v;
}

void Packet::set_size(unsigned int s){
    size = s;
}

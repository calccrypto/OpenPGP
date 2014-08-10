#include "packet.h"
std::string Packet::write_old_length(std::string data) const{
    unsigned int length = data.size();
    std::string out(1, 0b10000000 | (tag << 2));
    if (length < 256){
        out[0] |= 0;                                                       // 1 octet
        out += std::string(1, length);
    }
    else if ((256 <= length) && (length < 65536)){
        out[0] |= 1;
        out += unhexlify(makehex(length, 4));
    }
    else if (65536 <= length){
        out[0] |= 2;                                                      // 4 octets
        out += unhexlify(makehex(length, 8));
    }
    else{
        out[0] |= 3;
    }
    return out + data;
}

// returns formatted length string
std::string Packet::write_new_length(std::string data) const{
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

Packet::Packet(uint8_t tag, uint8_t version) :
    tag(tag),
    version(version),
    format(true),
    size(0)
{}

Packet::Packet(uint8_t tag) :
    Packet(tag, 0)
{}

Packet::Packet() :
    Packet(0)
{}

Packet::~Packet(){}

std::string Packet::write(uint8_t header) const{
    if ((header && ((header == 2) ||                                      // if user set new packet header or
       ((header == 1) && (tag > 15)))) ||                                 // if user set new packet header but tag is greater than 15 or
       (!header && ((format || ((!format) && (tag > 15)))))){             // if user did not set packet header and format is new, or format is old but tag is greater than 15
        return write_new_length(raw());
    }
    return write_old_length(raw());
}

uint8_t Packet::get_tag() const{
    return tag;
}

bool Packet::get_format() const{
    return format;
}

unsigned int Packet::get_version() const{
    return version;
}

unsigned int Packet::get_size() const{
    return size;
}

void Packet::set_tag(const uint8_t t){
    tag = t;
}

void Packet::set_format(const bool f){
    format = f;
}

void Packet::set_version(const unsigned int v){
    version = v;
}

void Packet::set_size(const unsigned int s){
    size = s;
}

Packet::Packet(const Packet &copy) :
    tag(copy.tag),
    version(copy.version),
    format(copy.format),
    size(copy.size)
{}


Packet & Packet::operator =(const Packet & copy)
{
    tag = copy.tag;
    version = copy.version;
    format = copy.format;
    size = copy.size;
    return *this;
}

// explicitly that it is inheritable.
Key::~Key(){}
ID::~ID(){}

Key & Key::operator =(const Key & copy)
{
    Packet::operator =(copy);
    return *this;
}

ID & ID::operator =(const ID & copy)
{
    Packet::operator =(copy);
    return *this;
}

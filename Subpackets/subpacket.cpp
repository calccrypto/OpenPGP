#include "subpacket.h"

std::string Subpacket::write_subpacket(const std::string & data) const{
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

std::string Subpacket::show_title() const{
    std::stringstream out;
    out << "        " << Subpacket_Tags.at(type) << " Subpacket (sub " << static_cast <unsigned int> (type) << ") (" << size << " octets)";
    return out.str();
}

Subpacket::Subpacket(uint8_t type, unsigned int size):
    type(type),
    size(size)
{}

Subpacket::~Subpacket(){}

std::string Subpacket::write() const{
    return write_subpacket(std::string(1, type) + raw());
}

uint8_t Subpacket::get_type() const{
    return type;
}

unsigned int Subpacket::get_size() const{
    return size;
}

void Subpacket::set_type(uint8_t t){
    type = t;
}

void Subpacket::set_size(unsigned int s){
    size = s;
}

Subpacket::Subpacket(const Subpacket & copy):
    type(copy.type),
    size(copy.size)
{}

Subpacket & Subpacket::operator =(const Subpacket & copy){
    type = copy.type;
    size = copy.size;
    return *this;
}

Tag2Subpacket::~Tag2Subpacket(){}

Tag17Subpacket::~Tag17Subpacket(){}

Tag2Subpacket & Tag2Subpacket::operator =(const Tag2Subpacket & copy){
    Subpacket::operator =(copy);
    return *this;
}

Tag17Subpacket & Tag17Subpacket::operator =(const Tag17Subpacket & copy){
    Subpacket::operator =(copy);
    return *this;
}

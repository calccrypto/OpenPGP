#include "Subpacket.h"

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
    if (critical){
        return "Critical: ";
    }

    return "";
}

Subpacket::Subpacket(uint8_t type, unsigned int size, bool crit)
    : critical(crit),
      type(type),
      size(size)
{}

Subpacket::Subpacket(const Subpacket & copy)
    : critical(copy.critical),
      type(copy.type),
      size(copy.size)
{}

Subpacket & Subpacket::operator=(const Subpacket & copy){
    type = copy.type;
    size = copy.size;
    return *this;
}

Subpacket::~Subpacket(){}

std::string Subpacket::write() const{
    return write_subpacket(std::string(1, type | (critical?0x80:0x00)) + raw());
}

uint8_t Subpacket::get_type() const{
    return type;
}

std::size_t Subpacket::get_size() const{
    return size;
}

void Subpacket::set_critical(const bool c){
    critical = c;
}

void Subpacket::set_type(const uint8_t t){
    type = t;
}

void Subpacket::set_size(const std::size_t s){
    size = s;
}

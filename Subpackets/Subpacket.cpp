#include "Subpacket.h"

namespace OpenPGP {
namespace Subpacket {

std::string Sub::write_SUBPACKET(const std::string & data) const{
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

std::string Sub::show_title() const{
    if (critical){
        return "Critical: ";
    }

    return "";
}

Sub::Sub(uint8_t type, unsigned int size, bool crit)
    : critical(crit),
      type(type),
      size(size)
{}

Sub::Sub(const Sub & copy)
    : critical(copy.critical),
      type(copy.type),
      size(copy.size)
{}

Sub & Sub::operator=(const Sub & copy){
    type = copy.type;
    size = copy.size;
    return *this;
}

Sub::~Sub(){}

std::string Sub::write() const{
    return write_SUBPACKET(std::string(1, type | (critical?0x80:0x00)) + raw());
}

uint8_t Sub::get_type() const{
    return type;
}

std::size_t Sub::get_size() const{
    return size;
}

void Sub::set_critical(const bool c){
    critical = c;
}

void Sub::set_type(const uint8_t t){
    type = t;
}

void Sub::set_size(const std::size_t s){
    size = s;
}

}
}
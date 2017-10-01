#include "Subpacket.h"

namespace OpenPGP {
namespace Subpacket {

std::string Base::write_SUBPACKET(const std::string & data) const{
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

std::string Base::show_title() const{
    if (critical){
        return "Critical: ";
    }

    return "";
}

Base::Base(uint8_t type, unsigned int size, bool crit)
    : critical(crit),
      type(type),
      size(size)
{}

Base::Base(const Base & copy)
    : critical(copy.critical),
      type(copy.type),
      size(copy.size)
{}

Base & Base::operator=(const Base & copy){
    type = copy.type;
    size = copy.size;
    return *this;
}

Base::~Base(){}

std::string Base::write() const{
    return write_SUBPACKET(std::string(1, type | (critical?0x80:0x00)) + raw());
}

uint8_t Base::get_type() const{
    return type;
}

std::size_t Base::get_size() const{
    return size;
}

void Base::set_critical(const bool c){
    critical = c;
}

void Base::set_type(const uint8_t t){
    type = t;
}

void Base::set_size(const std::size_t s){
    size = s;
}

}
}
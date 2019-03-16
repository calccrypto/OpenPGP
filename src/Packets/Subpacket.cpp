#include "Packets/Subpacket.h"

#include "Misc/Length.h"

namespace OpenPGP {
namespace Subpacket {

// Extracts Subpacket data for figuring which subpacket type to create
void Sub::read_subpacket(const std::string & data, std::string::size_type & pos, std::string::size_type & length) {
    const uint8_t first_octet = static_cast <unsigned char> (data[pos]);
    if (first_octet < 192) {
        read_one_octet_lengths(data, pos, length, Packet::HeaderFormat::NEW);
    }
    else if ((192 <= first_octet) && (first_octet < 255)) {
        read_two_octet_lengths(data, pos, length, Packet::HeaderFormat::NEW);
    }
    else{ // if (first_octet == 255) {
        read_five_octet_lengths(data, pos, length, Packet::HeaderFormat::NEW);
    }
}

std::string Sub::show_critical() const {
    if (critical) {
        return "Critical: ";
    }

    return "";
}

std::string Sub::write_subpacket(const std::string & data) const {
    if (data.size() < 192) {
        return std::string(1, data.size()) + data;
    }
    else if ((192 <= data.size()) && (data.size() < 8383)) {
        const uint16_t length = data.size() - 0xc0;
        return std::string(1, (length >> 8) + 0xc0) + std::string(1, length & 0xff) + data;
    }

    return "\xff" + unhexlify(makehex(data.size(), 8)) + data;
}

Sub::Sub(uint8_t type, unsigned int size, bool crit)
    : critical(crit),
      type(type),
      size(size)
{}

Sub::~Sub() {}

void Sub::read(const std::string & data) {
    if (data.size()) {
        size = data.size();
        actual_read(data);
    }
}

std::string Sub::show(const std::size_t indents, const std::size_t indent_size) const {
    HumanReadable hr(indent_size, indents);
    show(hr);
    return hr.get();
}

void Sub::show(HumanReadable & hr) const {
    hr << show_critical() + show_type() << HumanReadable::DOWN;
    show_contents(hr);
    hr << HumanReadable::UP;
}

std::string Sub::raw() const {
    return "";
}

std::string Sub::write() const {
    return write_subpacket(std::string(1, type | (critical?0x80:0x00)) + raw());
}

bool Sub::get_critical() const {
    return critical;
}

uint8_t Sub::get_type() const {
    return type;
}

std::size_t Sub::get_size() const {
    return size;
}

void Sub::set_critical(const bool c) {
    critical = c;
}

void Sub::set_type(const uint8_t t) {
    type = t;
}

void Sub::set_size(const std::size_t s) {
    size = s;
}

}
}

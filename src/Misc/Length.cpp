#include "Misc/Length.h"

#include "common/includes.h"

namespace OpenPGP {

std::size_t read_one_octet_lengths(const std::string & data, std::string::size_type & pos, std::size_t &length, const Packet::HeaderFormat) {
    length = static_cast <uint8_t> (data[pos]);
    pos += 1;
    return 1;
}

std::size_t read_two_octet_lengths(const std::string & data, std::string::size_type & pos, std::size_t &length, const Packet::HeaderFormat format) {
    if (format == Packet::HeaderFormat::OLD) {
        length = toint(data.substr(pos, 2), 256);
    }
    else {
        length = ((((uint8_t) data[pos]) - 192) << 8) + ((uint8_t) data[pos + 1]) + 192;
    }
    pos += 2;
    return 2;
}

std::size_t read_five_octet_lengths(const std::string & data, std::string::size_type & pos, std::size_t &length, const Packet::HeaderFormat) {
    length = toint(data.substr(pos + 1, 4), 256);
    pos += 5;
    return 5;
}

std::size_t read_partialBodyLen(uint8_t first_octet, const Packet::HeaderFormat) {
    return 1ULL << (first_octet & 0x1fU);
}

}

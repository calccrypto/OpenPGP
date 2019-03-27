#include "Misc/Length.h"

#include <list>

#include "Packets/Partial.h"
#include "common/includes.h"

namespace OpenPGP {

std::size_t read_one_octet_lengths(const std::string & data, std::string::size_type & pos, std::size_t & length, const Packet::HeaderFormat) {
    length = static_cast <uint8_t> (data[pos]);
    pos += 1;
    return 1;
}

std::size_t read_two_octet_lengths(const std::string & data, std::string::size_type & pos, std::size_t & length, const Packet::HeaderFormat format) {
    if (format == Packet::HeaderFormat::OLD) {
        length = toint(data.substr(pos, 2), 256);
    }
    else {
        length = ((((uint8_t) data[pos]) - 192) << 8) + ((uint8_t) data[pos + 1]) + 192;
    }
    pos += 2;
    return 2;
}

std::size_t read_five_octet_lengths(const std::string & data, std::string::size_type & pos, std::size_t & length, const Packet::HeaderFormat) {
    length = toint(data.substr(pos + 1, 4), 256);
    pos += 5;
    return 5;
}

std::size_t read_partialBodyLen(uint8_t first_octet, const Packet::HeaderFormat) {
    return 1ULL << (first_octet & 0x1fU);
}

// returns formatted length string
// partial takes precedence over octets
std::string write_old_length(const uint8_t tag, const std::string & data, const Packet::PartialBodyLength part, uint8_t octets) {
    std::string::size_type length = data.size();
    std::string out(1, 0x80 | (tag << 2)); // old header: 10TT TTLL
    if (part == Packet::PARTIAL) {         // partial
        out[0] |= 3;
    }
    else{
        // try to use user requested octet length
        if (octets == 1) {
            if (length > 255) {
                octets = 0;
            }
        }
        else if (octets == 2) {
            if (length > 65535) {
                octets = 0;
            }
        }
        else if ((octets == 3) ||
                 (octets == 4) ||
                 (octets >  5)) {
            octets = 0;
        }

        // 1 octet
        if ((octets == 1)   ||             // user requested
            ((octets == 0)  &&             // default
             (length < 256))) {
            out[0] |= 0;
            out += std::string(1, length);
        }
        // 2 octest
        else if ((octets == 2)     ||      // user requested
                 ((octets == 0)    &&      // default
                  (256 <= length)  &&
                  (length < 65536))) {
            out[0] |= 1;
            out += unhexlify(makehex(length, 4));
        }
        // 5 octets
        else if ((octets == 5)      ||     // use requested
                 ((octets == 0)     &&     // default
                  (65536 <= length))) {
            out[0] |= 2;
            out += unhexlify(makehex(length, 8));
        }
    }
    return out + data;
}

// returns formatted length string
// partial takes precedence over octets
std::string write_new_length(const uint8_t tag, const std::string & data, const Packet::PartialBodyLength part, uint8_t octets) {
    std::string::size_type length = data.size();
    std::string out(1, 0xc0 | tag);                         // new header: 11TT TTTT
    if (part == Packet::PARTIAL) {                          // partial
        if (length < 512) {
            throw std::runtime_error("The first partial length MUST be at least 512 octets long.");
        }

        // get the lowest 9 bits worth of octets to use as the last body length header
        const uint32_t non_partial = length & 511;

        // zero out the lowest 9 bits
        length &= ~511;

        // get the remaining bits that are set
        std::list <uint8_t> set_bits;
        for(uint8_t i = 9; i < 31; i++) {
            if (length & (1u << i)) {
                set_bits.push_front(i);
            }
        }

        // write partial body lengths
        uint32_t pos = 0;
        for(uint8_t const bit : set_bits) {
            const uint32_t partial_length = 1 << bit;
            out += std::string(1, bit | 0xe0);              // length with mask
            out += data.substr(pos, partial_length);        // data
            pos += partial_length;                          // increment offset
        }

        // write the last length header, which should not be a partial body length header
        out += write_new_length(tag, data.substr(pos, non_partial), Packet::NOT_PARTIAL);
    }
    else{
        // try to use user requested octet length
        if (octets == 1) {
            if (length > 191) {
                octets = 0;
            }
        }
        else if (octets == 2) {
            if (length > 8382) {
                octets = 0;
            }
        }
        else if ((octets == 3) ||
                 (octets == 4) ||
                 (octets >  5)) {
            octets = 0;
        }

        // 1 octet
        if ((octets == 1)     ||          // user requested
            ((octets == 0)    &&          // default
             (length <= 191))) {
            out += std::string(1, length);
        }
        // 2 octets
        else if ((octets == 2)        ||  // user requested
                 ((octets == 0)       &&  // default
                  ((192 <= length)    &&
                   (length <= 8383)))) {
            length -= 0xc0;
            out += std::string(1, (length >> 8) + 0xc0) + std::string(1, length & 0xff);
        }
        // 5 octets
        else if ((octets == 5)     ||     // user requested
                 ((octets == 0)    &&     // default
                  (length > 8383))) {
            out += std::string(1, '\xff') + unhexlify(makehex(length, 8));
        }

        out += data;
    }

    return out;
}

}

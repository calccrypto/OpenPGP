#include "Packets/Packet.h"

namespace OpenPGP {
namespace Packet {

bool is_key_packet(const uint8_t t){
    return (is_primary_key(t) || is_subkey(t));
}

bool is_primary_key(const uint8_t t){
    return ((t == SECRET_KEY) ||
            (t == PUBLIC_KEY));
}

bool is_subkey(const uint8_t t){
    return ((t == SECRET_SUBKEY) ||
            (t == PUBLIC_SUBKEY));
}

bool is_public(const uint8_t t){
    return ((t == PUBLIC_KEY) ||
            (t == PUBLIC_SUBKEY));
}

bool is_secret(const uint8_t t){
    return ((t == SECRET_KEY) ||
            (t == SECRET_SUBKEY));
}

bool is_user(const uint8_t t){
    return ((t == USER_ID) ||
            (t == USER_ATTRIBUTE));
}

bool is_session_key(const uint8_t t){
    return ((t == PUBLIC_KEY_ENCRYPTED_SESSION_KEY) ||
            (t == SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY));
}

bool is_sym_protected_data(const uint8_t t){
    return ((t == SYMMETRICALLY_ENCRYPTED_DATA) ||
            (t == SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA));
}

// returns formatted length string
std::string Tag::write_old_length(const uint8_t tag, const std::string & data, const uint8_t part){
    std::string::size_type length = data.size();
    std::string out(1, 0x80 | (tag << 2));                  // old header: 10TT TTLL
    if (part == Packet::Partial::PARTIAL){                  // partial
        out[0] |= 3;
    }
    else{
        if (length < 256){
            out[0] |= 0;                                    // 1 octet
            out += std::string(1, length);
        }
        else if ((256 <= length) && (length < 65536)){      // 2 octest
            out[0] |= 1;
            out += unhexlify(makehex(length, 4));
        }
        else if (65536 <= length){                          // 4 octets
            out[0] |= 2;
            out += unhexlify(makehex(length, 8));
        }
    }
    return out + data;
}

// returns formatted length string
std::string Tag::write_new_length(const uint8_t tag, const std::string & data, const uint8_t part){
    std::string::size_type length = data.size();
    std::string out(1, 0xc0 | tag);                         // new header: 11TT TTTT
    if (part == Packet::Partial::PARTIAL){                  // partial
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
            out += std::string(1, bit + 0x1f);              // length with mask
            out += data.substr(pos, partial_length);        // data
            pos += partial_length;                          // increment offset
        }

        // write the last length header, which should not be a partial body length header
        out += write_new_length(tag, data.substr(pos, non_partial), Packet::Partial::NOT_PARTIAL);
    }
    else{
        if (length < 192){                                  // 1 octet
            out += std::string(1, length);
        }
        else if ((192 <= length) && (length < 8383)){       // 2 octets
            length -= 0xc0;
            out += std::string(1, (length >> 8) + 0xc0 ) + std::string(1, length & 0xff);
        }
        else if (length > 8383){                            // 3 octets
            out += std::string(1, '\xff') + unhexlify(makehex(length, 8));
        }
    }
    return out + data;
}

std::string Tag::show_title() const{
    return (format?std::string("New"):std::string("Old")) + ": " + NAME.at(tag) + " (Tag " + std::to_string(tag) + ")";
}

Tag::Tag(const uint8_t t)
    : Tag(t, 0)
{}

Tag::Tag(const uint8_t t, uint8_t ver)
    : tag(t),
      version(ver),
      format(NEW),
      size(0)
{}

Tag::Tag(const Tag & copy)
    : tag(copy.tag),
      version(copy.version),
      format(copy.version),
      size(copy.size)
{}

Tag::Tag()
    : Tag(UNKNOWN)
{}

Tag::~Tag(){}

std::string Tag::write(const Tag::Format header) const{
    const std::string data = raw();
    if ((header == NEW) ||      // specified new header
        (tag > 15)){            // tag > 15, so new header is required
        return write_new_length(tag, data, Packet::Partial::NOT_PARTIAL);
    }
    return write_old_length(tag, data, Packet::Partial::NOT_PARTIAL);
}

uint8_t Tag::get_tag() const{
    return tag;
}

bool Tag::get_format() const{
    return format;
}

uint8_t Tag::get_version() const{
    return version;
}

std::size_t Tag::get_size() const{
    return size;
}

void Tag::set_tag(const uint8_t t){
    tag = t;
}

void Tag::set_format(const bool f){
    format = f;
}

void Tag::set_version(const uint8_t v){
    version = v;
}

void Tag::set_size(const std::size_t s){
    size = s;
}

Tag & Tag::operator=(const Tag & copy)
{
    tag = copy.tag;
    version = copy.version;
    format = copy.format;
    size = copy.size;
    return *this;
}

}
}

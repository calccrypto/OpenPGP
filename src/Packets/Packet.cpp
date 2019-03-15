#include "Packets/Packet.h"

#include <cstdint>
#include <list>

#include "common/includes.h"
#include "Packets/Partial.h"

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

bool can_have_partial_length (const uint8_t t){
    return Partial::can_have_partial_length(t);
}

std::string Tag::show_title() const{
    return ((header_format == HeaderFormat::NEW)?std::string("New"):std::string("Old")) + ": " + NAME.at(tag) + " (Tag " + std::to_string(tag) + ")";
}

void Tag::show_contents(HumanReadable &) const{}

// returns formatted length string
// partial takes precedence over octets
std::string Tag::write_old_length(const uint8_t tag, const std::string & data, const PartialBodyLength part, uint8_t octets){
    std::string::size_type length = data.size();
    std::string out(1, 0x80 | (tag << 2)); // old header: 10TT TTLL
    if (part == Packet::PARTIAL){          // partial
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
             (length < 256))){
            out[0] |= 0;
            out += std::string(1, length);
        }
        // 2 octest
        else if ((octets == 2)     ||      // user requested
                 ((octets == 0)    &&      // default
                  (256 <= length)  &&
                  (length < 65536))){
            out[0] |= 1;
            out += unhexlify(makehex(length, 4));
        }
        // 5 octets
        else if ((octets == 5)      ||     // use requested
                 ((octets == 0)     &&     // default
                  (65536 <= length))){
            out[0] |= 2;
            out += unhexlify(makehex(length, 8));
        }
    }
    return out + data;
}

// returns formatted length string
// partial takes precedence over octets
std::string Tag::write_new_length(const uint8_t tag, const std::string & data, const PartialBodyLength part, uint8_t octets){
    std::string::size_type length = data.size();
    std::string out(1, 0xc0 | tag);                         // new header: 11TT TTTT
    if (part == Packet::PARTIAL){                           // partial
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

Tag::Tag(const uint8_t t)
    : Tag(t, 0)
{}

Tag::Tag(const uint8_t t, uint8_t ver)
    : tag(t),
      version(ver),
      header_format(HeaderFormat::NEW),
      size(0)
{}

Tag::Tag()
    : Tag(UNKNOWN)
{}

Tag::~Tag(){}

void Tag::read(const std::string &data) {
    // set size first, in case the size variable is needed during actual_read
    // the size won't change during actual_read, so there is no need to reset it after
    set_size(data.size());
    if (size) {
        actual_read(data);
    }
}

std::string Tag::show(const std::size_t indents, const std::size_t indent_size) const{
    HumanReadable hr(indent_size, indents);
    show(hr);
    return hr.get();
}

void Tag::show(HumanReadable & hr) const{
    hr << show_title() << HumanReadable::DOWN;
    show_contents(hr);
    hr << HumanReadable::UP;
}

std::string Tag::write() const{
    const std::string data = raw();
    if ((header_format == HeaderFormat::NEW) || // specified new header
        (tag > 15)){                            // tag > 15, so new header is required
        return write_new_length(tag, data, Packet::NOT_PARTIAL);
    }
    return write_old_length(tag, data, Packet::NOT_PARTIAL);
}

uint8_t Tag::get_tag() const{
    return tag;
}

Packet::HeaderFormat Tag::get_header_format() const{
    return header_format;
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

void Tag::set_header_format(const HeaderFormat hf){
    header_format = hf;
}

void Tag::set_version(const uint8_t v){
    version = v;
}

void Tag::set_size(const std::size_t s){
    size = s;
}

}
}

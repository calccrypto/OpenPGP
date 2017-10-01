#include "Packet.h"

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

std::string Base::write_old_length(const std::string & data) const{
    std::string::size_type length = data.size();
    std::string out(1, 0b10000000 | (tag << 2));
    if (partial){
        out[0] |= 3;                                        // partial
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
std::string Base::write_new_length(const std::string & data) const{
    std::string::size_type length = data.size();
    std::string out(1, 0b11000000 | tag);
    if (partial){                                           // partial
        uint8_t bits = 0;
        while (length > (1u << bits)){
            bits++;
        }
        length = 224 + bits;
        if (length > 254){
            throw std::runtime_error("Error: Data in partial Base too large.");
        }

        out += std::string(1, length);
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

std::string Base::show_title() const{
    std::string out = std::string(format?"New":"Old") + ": " + NAME.at(tag) + " (Tag " + std::to_string(tag) + ")";

    switch (partial){
        case 0:
            break;
        case 1:
            out += " (partial start)";
            break;
        case 2:
            out += " (partial continue)";
            break;
        case 3:
            out += " (partial end)";
            break;
        default:
            throw std::runtime_error("Error: Unknown partial type: " + std::to_string(partial));
            break;
    }
    return out;
}

Base::Base(const uint8_t t)
    : Base(t, 0)
{}

Base::Base(const uint8_t t, uint8_t ver)
    : tag(t),
      version(ver),
      format(true),
      size(0),
      partial(0)
{}

Base::Base(const Base & copy)
    : tag(copy.tag),
      version(copy.version),
      format(copy.version),
      size(copy.size),
      partial(copy.partial)
{}

Base::Base()
    : Base(UNKNOWN)
{}

Base::~Base(){}

std::string Base::write(const Base::Format header) const{
    if ((header == NEW) ||      // specified new header
        (tag > 15)){            // tag > 15, so new header is required
        return write_new_length(raw());
    }
    return write_old_length(raw());
}

uint8_t Base::get_tag() const{
    return tag;
}

bool Base::get_format() const{
    return format;
}

uint8_t Base::get_version() const{
    return version;
}

std::size_t Base::get_size() const{
    return size;
}

uint8_t Base::get_partial() const{
    return partial;
}

void Base::set_tag(const uint8_t t){
    tag = t;
}

void Base::set_format(const bool f){
    format = f;
}

void Base::set_version(const uint8_t v){
    version = v;
}

void Base::set_size(const std::size_t s){
    size = s;
}

void Base::set_partial(const uint8_t p){
    partial = p;
}

Base & Base::operator=(const Base & copy)
{
    tag = copy.tag;
    version = copy.version;
    format = copy.format;
    size = copy.size;
    partial = copy.partial;
    return *this;
}

}
}

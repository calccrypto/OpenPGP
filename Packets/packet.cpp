#include "packet.h"

std::string Packet::write_old_length(const std::string & data) const{
    std::string::size_type length = data.size();
    std::string out(1, 0b10000000 | (tag << 2));
    if (partial){
        out[0] |= 3;                                        // partial
    }
    else {
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
std::string Packet::write_new_length(const std::string & data) const{
    std::string::size_type length = data.size();
    std::string out(1, 0b11000000 | tag);
    if (partial){                                           // partial
        uint8_t bits = 0;
        while (length > (1u << bits)){
            bits++;
        }
        length = 224 + bits;
        if (length > 254){
            throw std::runtime_error("Error: Data in partial packet too large.");
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

std::string Packet::show_title() const{
    std::stringstream out;
    out << (format?"New":"Old") << ": " << Packet_Tags.at(tag) << " (Tag " << static_cast <unsigned int> (tag) << ")";

    switch (partial){
        case 0:
            break;
        case 1:
            out << " (partial start)";
            break;
        case 2:
            out << " (partial continue)";
            break;
        case 3:
            out << " (partial end)";
            break;
        default:
            {
                std::stringstream s; s << static_cast <unsigned int> (partial);
                throw std::runtime_error("Error: Unknown partial type: " + s.str());
            }
            break;
    }
    return out.str();
}

Packet::Packet(uint8_t tag, uint8_t version)
    : tag(tag),
      version(version),
      format(true),
      size(0),
      partial(0)
{}

Packet::Packet(uint8_t tag)
    : Packet(tag, 0)
{}

Packet::Packet()
    : Packet(0)
{}

Packet::~Packet(){}

std::string Packet::write(uint8_t header) const{
    if ((header && ((header == 2) ||                          // if user set new packet header or
       ((header == 1) && (tag > 15)))) ||                     // if user set new packet header but tag is greater than 15 or
       (!header && ((format || ((!format) && (tag > 15)))))){ // if user did not set packet header and format is new, or format is old but tag is greater than 15
        return write_new_length(raw());
    }
    return write_old_length(raw());
}

uint8_t Packet::get_tag() const{
    return tag;
}

bool Packet::get_format() const{
    return format;
}

unsigned int Packet::get_version() const{
    return version;
}

unsigned int Packet::get_size() const{
    return size;
}

uint8_t Packet::get_partial() const{
    return partial;
}

void Packet::set_tag(const uint8_t t){
    tag = t;
}

void Packet::set_format(const bool f){
    format = f;
}

void Packet::set_version(const unsigned int v){
    version = v;
}

void Packet::set_size(const unsigned int s){
    size = s;
}

void Packet::set_partial(const uint8_t p){
    partial = p;
}

Packet::Packet(const Packet &copy)
    : tag(copy.tag),
      version(copy.version),
      format(copy.format),
      size(copy.size),
      partial(copy.partial)
{}

Packet & Packet::operator=(const Packet & copy)
{
    tag = copy.tag;
    version = copy.version;
    format = copy.format;
    size = copy.size;
    partial = copy.partial;
    return *this;
}

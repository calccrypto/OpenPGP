#include "packets.h"

unsigned int partialBodyLen(uint8_t first_octet){
    return 1 << (first_octet & 0x1f);
}

std::string read_packet_header(std::string & data, uint8_t & tag, bool & format, uint8_t & partial){
    uint8_t ctb = data[0];		                                           // Name "ctb" came from Version 2 [RFC 1991]
    format = ctb & 0x40;                                                   // get packet length type (OLD = false; NEW = true)
    unsigned int remove = 1;                                               // how much more stuff to remove from raw string
    unsigned int length = 0;                                               // length of the data without the header

    if (!partial){                                                         // if partial continue packets have not been found
        if (!(ctb & 0x80)){
           throw std::runtime_error("Error: First bit of packet header MUST be 1.");
        }

        if (!format){                                                      // Old length type RFC4880 sec 4.2.1
            tag = (ctb >> 2) & 15;                                         // get tag value
            if ((ctb & 3) == 0){                                           // 0 - The packet has a one-octet length. The header is 2 octets long.
                remove += 1;
                length = static_cast <uint8_t> (data[1]);
            }
            else if ((ctb & 3) == 1){                                      // 1 - The packet has a two-octet length. The header is 3 octets long.
                remove += 2;
                length = toint(data.substr(1, 2), 256);
            }
            else if ((ctb & 3) == 2){                                      // 2 - The packet has a four-octet length. The header is 5 octets long.
                remove += 5;
                length = toint(data.substr(2, 5), 256);
            }
            else if ((ctb & 3) == 3){                                      // The packet is of indeterminate length. The header is 1 octet long, and the implementation must determine how long the packet is.
                partial = 1;                                               // set to partial start
                // remove += 0;
                length = data.size() - 1;                                  // header is one octet long
            }
        }
        else{   												           // New length type RFC4880 sec 4.2.2
            tag = ctb & 63;                                                // get tag value
            uint8_t first_octet = static_cast <unsigned char> (data[1]);
            if (first_octet < 192){                                        // 0 - 191; A one-octet Body Length header encodes packet lengths of up to 191 octets.
                remove += 1;
                length = first_octet;
            }
            else if ((192 <= first_octet) & (first_octet < 223)){          // 192 - 8383; A two-octet Body Length header encodes packet lengths of 192 to 8383 octets.
                remove += 2;
                length = toint(data.substr(1, 2), 256) - (192 << 8) + 192;
            }
            else if (first_octet == 255){                                  // 8384 - 4294967295; A five-octet Body Length header encodes packet lengths of up to 4,294,967,295 (0xFFFFFFFF) octets in length.
                remove += 5;
                length = toint(data.substr(2, 4), 256);
            }
            else if (224 <= first_octet){                                  // unknown; When the length of the packet body is not known in advance by the issuer, Partial Body Length headers encode a packet of indeterminate length, effectively making it a stream.
                partial = 1;                                               // set to partial start
                // remove += 0;
                length = partialBodyLen(first_octet);
            }
        }
    }
    else{ // partial continue
        if (!format){                                                      // Old length type RFC4880 sec 4.2.1
            tag = 254;                                                     // set to partial body tag
            // remove += 0;                                                // set to partial continue
            length = data.size() - 1;                                      // header is one octet long
            partial = 2;
        }
        else{   												           // New length type RFC4880 sec 4.2.2
            tag = 254;                                                     // set to partial body tag
            // remove += 0;
            length = partialBodyLen(data[1]);
            partial = 2;                                                   // set to partial continue
        }
    }
    std::string packet = data.substr(remove, length);						// Get packet
    data = data.substr(remove + length, data.size() - remove - length);		// Remove packet from key
    return packet;
}

Packet::Ptr read_packet_raw(const bool format, const uint8_t tag, uint8_t & partial, std::string & packet_data){
    Packet::Ptr out;
    if (partial > 1){
        out = std::make_shared<Partial>();
    }
    else{
        switch (tag){
            case 0:
                throw std::runtime_error("Error: Tag number MUST NOT be 0.");
                break;
            case 1:
                out = std::make_shared<Tag1>();
                break;
            case 2:
                out = std::make_shared<Tag2>();
                break;
            case 3:
                out = std::make_shared<Tag3>();
                break;
            case 4:
                out = std::make_shared<Tag4>();
                break;
            case 5:
                out = std::make_shared<Tag5>();
                break;
            case 6:
                out = std::make_shared<Tag6>();
                break;
            case 7:
                out = std::make_shared<Tag7>();
                break;
            case 8:
                out = std::make_shared<Tag8>();
                break;
            case 9:
                out = std::make_shared<Tag9>();
                break;
            case 10:
                out = std::make_shared<Tag10>();
                break;
            case 11:
                out = std::make_shared<Tag11>();
                break;
            case 12:
                out = std::make_shared<Tag12>();
                break;
            case 13:
                out = std::make_shared<Tag13>();
                break;
            case 14:
                out = std::make_shared<Tag14>();
                break;
            case 17:
                out = std::make_shared<Tag17>();
                break;
            case 18:
                out = std::make_shared<Tag18>();
                break;
            case 19:
                out = std::make_shared<Tag19>();
                break;
            case 60:
                out = std::make_shared<Tag60>();
                break;
            case 61:
                out = std::make_shared<Tag61>();
                break;
            case 62:
                out = std::make_shared<Tag62>();
                break;
            case 63:
                out = std::make_shared<Tag63>();
                break;
            default:
                throw std::runtime_error("Error: Tag not defined.");
                break;
        }
    }

    // fill in data
    out -> set_tag(tag);
    out -> set_format(format);
    out -> set_partial(partial);
    out -> set_size(packet_data.size());
    out -> read(packet_data);

    if (partial){
        partial = 2;
    }

    return out;
}

Packet::Ptr read_packet(std::string & data, uint8_t & partial){
    bool format;
    uint8_t tag = 0;
    std::string packet_data = read_packet_header(data, tag, format, partial);
    return read_packet_raw(format, tag, partial, packet_data);
}

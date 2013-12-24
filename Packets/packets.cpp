#include "packets.h"

unsigned int partialBodyLen(uint8_t first_octet){
    return 1 << (first_octet & 0x1f);
}

std::string read_packet_header(std::string & data, uint8_t & tag, bool & format){
    uint8_t ctb = data[0];													    // Name "ctb" came from Version 2 [RFC 1991]
    if (!(ctb >> 7)){
        std::cerr << "Error: First bit of tag header MUST be 1" << std::endl;
        exit(1);
    }

    unsigned int length = 0;
    data = data.substr(1, data.size() - 1);                                     // get rid of ctb / first byte of header
    std::string packet;

    if (!((ctb >> 6) & 1)){                                                     // Old length type RFC4880 sec 4.2.1
        format = false;
        tag = (ctb >> 2) & 15;                                                  // get tag value
		if (!(ctb & 3)){
			length = (uint8_t) data[0];
			data = data.substr(1, data.size() - 1);                             // get rid of second byte of header
		}
		else if ((ctb & 3) == 1){
			length = toint(data.substr(0, 2), 256);
			data = data.substr(2, data.size() - 2);                             // get rid of second and third byte of header
		}
		else if ((ctb & 3) == 2){
			length = toint(data.substr(1, 5), 256);
			data = data.substr(6, data.size() - 6);                             // get rid of next 4 bytes
		}
		else if ((ctb & 3) == 3){                                               // indeterminate length; header is 1 octet long; packet continues until end of data
			length = data.size();
		}
    }
	else if ((ctb >> 6) & 1){   												// New length type RFC4880 sec 4.2.2
		format = true;
		tag = ctb & 63;                                                         // get tag value
		uint8_t first_octet = (unsigned char) data[0];
		if (first_octet < 192){                                                 // 0 - 192
			length = first_octet;
			data = data.substr(1, data.size() - 1);
		}
		else if ((192 <= first_octet) & (first_octet < 223)){                   // 193 - 8383
			length = toint(data.substr(0, 2), 256) - (192 << 8) + 192;
			data = data.substr(2, data.size() - 2);
		}
		else if (first_octet == 255){                                           // 8384 - 4294967295
			length = toint(data.substr(1, 4), 256);
			data = data.substr(5, data.size() - 5);
		}
		else if (224 <= first_octet){                                           // unknown
			tag = -1;                                                           // partial
			length = partialBodyLen(first_octet);
			data = data.substr(1, data.size() - 1);
		}
	}

	packet = data.substr(0, length);											// Get packet
	data = data.substr(length, data.size() - length);							// Remove packet from key
    return packet;
}

Packet * read_packet(uint8_t & tag, std::string & packet_data){
    Packet * out;
    switch (tag){
        case 0:
            std::cerr << "Error: Tag number MUST NOT be 0" << std::endl;
            exit(1);
            break;
        case 1:
            out = new Tag1;
            break;
        case 2:
            out = new Tag2;
            break;
        case 3:
            out = new Tag3;
            break;
        case 4:
            out = new Tag4;
            break;
        case 5:
            out = new Tag5;
            break;
        case 6:
            out = new Tag6;
            break;
        case 7:
            out = new Tag7;
            break;
        case 8:
            out = new Tag8;
            break;
        case 9:
            out = new Tag9;
            break;
        case 10:
            out = new Tag10;
            break;
        case 11:
            out = new Tag11;
            break;
        case 12:
            out = new Tag12;
            break;
        case 13:
            out = new Tag13;
            break;
        case 14:
            out = new Tag14;
            break;
        case 17:
            out = new Tag17;
            break;
        case 18:
            out = new Tag18;
            break;
        case 19:
            out = new Tag19;
            break;
        default:
            std::cerr << "Error: Tag not defined or reserved" << std::endl;
            exit(1);
            break;
    }
    out -> set_size(packet_data.size());
    out -> read(packet_data);
    return out;
}


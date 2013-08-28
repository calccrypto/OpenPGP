#ifndef __PACKETS__
#define __PACKETS__

#include "Packets/packet.h"

#include "Packets/Tag0.h"
#include "Packets/Tag1.h"
#include "Packets/Tag2.h"
#include "Packets/Tag3.h"
#include "Packets/Tag4.h"
#include "Packets/Tag5.h"
#include "Packets/Tag6.h"
#include "Packets/Tag7.h"
#include "Packets/Tag8.h"
#include "Packets/Tag9.h"
#include "Packets/Tag10.h"
#include "Packets/Tag11.h"
#include "Packets/Tag12.h"
#include "Packets/Tag13.h"
#include "Packets/Tag14.h"
#include "Packets/Tag17.h"
#include "Packets/Tag18.h"
#include "Packets/Tag19.h"

// Functions that cannot be placed inside Packet class and are needed globally

// calculates the length of a pertial body
unsigned int partialBodyLen(uint8_t first_octet);

// Reads and removes packet header, returning the raw packet data. Input data is shortened
std::string read_packet_header(std::string & data, uint8_t & tag, bool & format);

// parses raw packet data
Packet * read_packet(uint8_t & tag, std::string & packet_data);

#endif

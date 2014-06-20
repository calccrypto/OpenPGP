#ifndef __PACKETS__
#define __PACKETS__

#include "packet.h"

#include "Tag0.h"
#include "Tag1.h"
#include "Tag2.h"
#include "Tag3.h"
#include "Tag4.h"
#include "Tag5.h"
#include "Tag6.h"
#include "Tag7.h"
#include "Tag8.h"
#include "Tag9.h"
#include "Tag10.h"
#include "Tag11.h"
#include "Tag12.h"
#include "Tag13.h"
#include "Tag14.h"
#include "Tag17.h"
#include "Tag18.h"
#include "Tag19.h"
#include "TagX.h"

// Functions that cannot be placed inside Packet class and are needed globally

// calculates the length of a pertial body
unsigned int partialBodyLen(uint8_t first_octet);

// reads and removes packet header, returning the raw packet data. Input data is shortened
std::string read_packet_header(std::string & data, uint8_t & tag, bool & format);

// parses raw packet data
Packet::Ptr read_packet_raw(const bool format, const uint8_t tag, std::string & packet_data);

// parse packet with header; wrapper for read_packet_header and read_packet_raw
Packet::Ptr read_packet(std::string & data);
#endif

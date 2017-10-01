#include "CRC-24.h"

namespace OpenPGP {

// OpenPGP has an optional CRC24 checksum at the end of its Radix-64 encoded data
uint32_t crc24(const std::string & str){
    static const uint32_t INIT = 0xB704CE;
    static const uint32_t POLY = 0x1864CFB;

    uint32_t crc = INIT;
    for(unsigned char const c : str){
        crc ^= static_cast <uint32_t> (c) << 16;
        for(uint8_t i = 0; i < 8; i++){
            crc <<= 1;
            if (crc & 0x1000000){
                crc ^= POLY;
            }
        }
    }

    return crc & 0xFFFFFF;
}

}
#include "radix64.h"

namespace OpenPGP {

std::string ascii2radix64(std::string str, const unsigned char char62, const unsigned char char63){
    std::string out = "", bin = "", pad = "";
    while (str.size() % 3){
        str += zero;
        pad += "=";
    }

    for(char const c : str){
        bin += makebin(c, 8);
    }

    std::string::size_type x = 0;
    while (x < bin.size()){
        out += ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" + std::string(1, char62) + std::string(1, char63))[toint(bin.substr(x, 6), 2)];
        x += 6;
    }

    if (pad.size() == 2){                       // string length % 3 == 1
        out = out.substr(0, out.size() - 2);
    }

    if (pad.size() == 1){                       // string length % 3 == 2
        out = out.substr(0, out.size() - 1);
    }

    return out + pad;
}

std::string radix642ascii(std::string str, const unsigned char char62, const unsigned char char63){
    if (str.size() & 3){
        throw std::runtime_error("Error: Input string length is not a multiple of 4.");
    }

    std::string bin = "";

    // count padding
    uint8_t unpad = 0;
    while (str[str.size() - 1] == '='){
        unpad++;
        str = str.substr(0, str.size() - 1);
    }

    for(unsigned char c : str){
        if (('A' <= c) && (c <= 'Z')){
            bin += makebin(c - 'A', 6);
        }
        else if (('a' <= c) && (c <= 'z')){
            bin += makebin(c - 'G', 6);
        }
        else if (('0' <= c) && (c <= '9')){
            bin += makebin(c + 4, 6);
        }
        else if (c == char62){
            bin += "111110";
        }
        else if (c == char63){
            bin += "111111";
        }
        else{
            throw std::runtime_error("Error: Invalid Radix64 character found: " + std::string(1, c));
        }
    }

    bin += std::string(unpad * 6, '0');

    str = "";
    for(unsigned int x = 0; x < bin.size(); x += 8){
        str += std::string(1, static_cast <unsigned char> (toint(bin.substr(x, 8), 2)));
    }

    return str.substr(0, str.size() - unpad);   // remove padding when returning
}

}
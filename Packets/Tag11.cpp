#include "Tag11.h"
Tag11::Tag11(){
    tag = 11;
}

Tag11::Tag11(std::string & data){
    tag = 11;
    read(data);
}

void Tag11::read(std::string & data){
    size = data.size();
    format = data[0];
    uint8_t len = data[1];
    filename = data.substr(2, len);
    time = toint(data.substr(2 + len, 4), 256);
    literal = data.substr(len + 6, data.size() - len - 6);
}

std::string Tag11::show(){
    std::stringstream out;
    out << "    Format: " << BTU.at(format) << "\n"
        << "    Data (" << (1 + filename.size() + 4 + literal.size()) << " octets): \n"
        << "        Filename: " << filename << "\n"
        << "        Creation Date: " << show_time(time) << "\n"
        << "        Data: " << literal << "\n";
    return out.str();
}

std::string Tag11::raw(){
    return std::string(1, format) + std::string(1, filename.size()) + filename + unhexlify(makehex(time, 8)) + literal;
}

uint8_t Tag11::get_format(){
    return format;
}

std::string Tag11::get_filename(){
    return filename;
}

uint32_t Tag11::get_time(){
    return time;
}

std::string Tag11::get_literal(){
    return literal;
}

void Tag11::set_format(const uint8_t f){
    format = f;
}

void Tag11::set_filename(const std::string & f){
    filename = f;
}

void Tag11::set_time(const uint32_t t){
    time = t;
}

void Tag11::set_literal(const std::string & l){
    literal = l;
}

Tag11 * Tag11::clone(){
    return new Tag11(*this);
}

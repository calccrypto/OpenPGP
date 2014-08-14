#include "Tag10.h"

Tag10::Tag10():
    Packet(10),
    pgp("PGP")
{}

Tag10::Tag10(std::string & data):
    Tag10()
{
    read(data);
}

void Tag10::read(std::string & data, const uint8_t part){
    size = data.size();
    if (data != "PGP"){
        throw std::runtime_error("Error: Tag 10 packet did not contain data \x5cPGP\x5c.");
    }
}

std::string Tag10::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    return std::string(tab, ' ') + std::string(tab, ' ') + show_title() + "\n" + std::string(tab, ' ') + "    PGP";
}

std::string Tag10::raw() const{
    return "PGP";
}

std::string Tag10::get_pgp() const{
    return pgp;
}

void Tag10::set_pgp(const std::string & s){
    if (s != "PGP"){
        throw std::runtime_error("Error: Tag 10 input data not string \x5cPGP\x5c.");
    }
    pgp = s;
    size = 3;
}

Packet::Ptr Tag10::clone() const{
    return std::make_shared <Tag10> (*this);
}

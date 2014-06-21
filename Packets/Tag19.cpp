#include "Tag19.h"

Tag19::Tag19() :
    Packet(19),
    hash()
{
    size = 20;
}

Tag19::Tag19(std::string & data) :
    Tag19()
{
    read(data);
}

void Tag19::read(std::string & data){
    size = data.size();
    hash = data;
}

std::string Tag19::show() const{
    std::stringstream out;
    out << "    SHA - 1 Hash of previous packet: " << hash << "\n";
    return out.str();
}

std::string Tag19::raw() const{
    return hash;
}

std::string Tag19::get_hash() const{
    return hash;
}

void Tag19::set_hash(const std::string & h){
    hash = h;
    size = raw().size();
}

Packet::Ptr Tag19::clone() const{
    return Ptr(new Tag19(*this));
}

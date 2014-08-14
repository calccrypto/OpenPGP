#include "Tag9.h"

Tag9::Tag9():
    Packet(9),
    encrypted_data()
{}

Tag9::Tag9(std::string & data):
    Tag9()
{
    read(data);
}

void Tag9::read(std::string & data, const uint8_t part){
    size = data.size();
    encrypted_data = data;
}

std::string Tag9::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::stringstream out;
    out << std::string(tab, ' ') << show_title() << "\n" << std::string(tab, ' ') << "    Encrypted Data (" << encrypted_data.size() << " octets): " << hexlify(encrypted_data);
    return out.str();
}

std::string Tag9::raw() const{
    return encrypted_data;
}

std::string Tag9::get_encrypted_data() const{
    return encrypted_data;
}

void Tag9::set_encrypted_data(const std::string & e){
    encrypted_data = e;
    size = raw().size();
}

Packet::Ptr Tag9::clone() const{
    return std::make_shared <Tag9> (*this);
}

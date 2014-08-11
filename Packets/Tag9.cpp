#include "Tag9.h"

Tag9::Tag9() :
    Packet(9),
    encrypted_data()
{}

Tag9::Tag9(std::string & data) :
    Tag9()
{
    read(data);
}

void Tag9::read(std::string & data){
    size = data.size();
    encrypted_data = data;
}

std::string Tag9::show(const uint8_t indents, const uint8_t indent_size) const{
    std::stringstream out;
    out << show_title(indents, indent_size) << "    Encrypted Data (" << encrypted_data.size() << " octets): " << hexlify(encrypted_data) << "\n";
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
    return Ptr(new Tag9(*this));
}

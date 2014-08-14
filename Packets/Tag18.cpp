#include "Tag18.h"

Tag18::Tag18():
    Packet(18, 1),
    protected_data()
{}

Tag18::Tag18(std::string & data):
    Tag18()
{
    read(data);
}

void Tag18::read(std::string & data, const uint8_t part){
    size = data.size();
    version = data[0];
    protected_data = data.substr(1, data.size() - 1);
}

std::string Tag18::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::stringstream out;
    out << std::string(tab, ' ') << show_title() << "\n"
        << std::string(tab, ' ') << "    Version: " << static_cast <unsigned int> (version) << "\n"
        << std::string(tab, ' ') << "    Encrypted Data (" << protected_data.size() << " octets): " << hexlify(protected_data);
    return out.str();
}

std::string Tag18::raw() const{
    return std::string(1, version) + protected_data;
}

std::string Tag18::get_protected_data() const{
    return protected_data;
}

void Tag18::set_protected_data(const std::string & p){
    protected_data = p;
    size = raw().size();
}

Packet::Ptr Tag18::clone() const{
    return std::make_shared <Tag18> (*this);
}

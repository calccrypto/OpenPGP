#include "Tag2Sub9.h"

Tag2Sub9::Tag2Sub9():
    Tag2Subpacket(9, 4),
    time()
{}

Tag2Sub9::Tag2Sub9(std::string & data):
    Tag2Sub9()
{
    read(data);
}

void Tag2Sub9::read(std::string & data){
    time = static_cast <time_t> (toint(data, 256));
}

std::string Tag2Sub9::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::stringstream out;
    out << std::string(tab, ' ') << show_title() << "\n"
        << std::string(tab, ' ') << "            Key Expiration Time (Days): ";
    if (time == 0){
        out << std::string(tab, ' ') << "Never";
    }
    else{
        out << std::string(tab, ' ') << show_time(time);
    }
    return out.str();
}

std::string Tag2Sub9::raw() const{
    return unhexlify(makehex(time, 8));
}

time_t Tag2Sub9::get_time() const{
    return time;
}

void Tag2Sub9::set_time(const time_t t){
    time = t;
}

Tag2Subpacket::Ptr Tag2Sub9::clone() const{
    return std::make_shared <Tag2Sub9> (*this);
}

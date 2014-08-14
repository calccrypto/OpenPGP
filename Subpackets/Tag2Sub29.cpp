#include "Tag2Sub29.h"

Tag2Sub29::Tag2Sub29():
    Tag2Subpacket(29),
    code(),
    reason()
{}

Tag2Sub29::Tag2Sub29(std::string & data):
    Tag2Sub29()
{
    read(data);
}

void Tag2Sub29::read(std::string & data){
    code = data[0];
    reason = data.substr(1, data.size() - 1);
    size = data.size();
}

std::string Tag2Sub29::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::stringstream out;
    out << std::string(tab, ' ') << show_title() << "\n"
        << std::string(tab, ' ') << "            Reason " << static_cast <unsigned int> (code) << " - " << Revoke.at(code);
    if (code){
        out << "\n" << std::string(tab, ' ') << "            Comment - " << reason;
    }
    return out.str();
}

std::string Tag2Sub29::raw() const{
    return std::string(1, code) + reason;
}

uint8_t Tag2Sub29::get_code() const{
    return code;
}

std::string Tag2Sub29::get_reason() const{
    return reason;
}

void Tag2Sub29::set_code(const uint8_t c){
    code = c;
}

void Tag2Sub29::set_reason(const std::string & r){
    reason = r;
}

Tag2Subpacket::Ptr Tag2Sub29::clone() const{
    return std::make_shared <Tag2Sub29> (*this);
}

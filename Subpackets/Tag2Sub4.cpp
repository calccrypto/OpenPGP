#include "Tag2Sub4.h"

Tag2Sub4::Tag2Sub4() :
    Tag2Subpacket(4, 1),
    exportable()
{}

Tag2Sub4::Tag2Sub4(std::string & data) :
    Tag2Sub4()
{
    read(data);
}

void Tag2Sub4::read(std::string & data){
    exportable = data[0];
}

std::string Tag2Sub4::show(const uint8_t indents, const uint8_t indent_size) const{
    return std::string(indents * indent_size, ' ') + std::string("            Exportable: ") + (exportable?"True":"False") + "\n";
}

std::string Tag2Sub4::raw() const{
    return (exportable?"\x01":zero);
}

bool Tag2Sub4::get_exportable() const{
    return exportable;
}

void Tag2Sub4::set_exportable(const bool e){
    exportable = e;
}

Tag2Subpacket::Ptr Tag2Sub4::clone() const{
    return Ptr(new Tag2Sub4(*this));
}

#include "Sub4.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

Sub4::Sub4()
    : Sub(EXPORTABLE_CERTIFICATION, 1),
      exportable()
{}

Sub4::Sub4(const std::string & data)
    : Sub4()
{
    read(data);
}

void Sub4::read(const std::string & data){
    if (data.size()){
        exportable = data[0];
    }
}

std::string Sub4::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "Exportable: " + (exportable?"True":"False");
}

std::string Sub4::raw() const{
    return (exportable?"\x01":zero);
}

bool Sub4::get_exportable() const{
    return exportable;
}

void Sub4::set_exportable(const bool e){
    exportable = e;
}

Sub::Ptr Sub4::clone() const{
    return std::make_shared <Sub4> (*this);
}

}
}
}
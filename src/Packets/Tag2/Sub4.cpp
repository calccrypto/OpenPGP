#include "Packets/Tag2/Sub4.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub4::actual_read(const std::string & data){
    if (data.size()){
        set_exportable(data[0]);
    }
}

void Sub4::show_contents(HumanReadable & hr) const{
    hr << std::string("Exportable: ") + (exportable?"True":"False");
}

Sub4::Sub4()
    : Sub(EXPORTABLE_CERTIFICATION, 1),
      exportable()
{}

Sub4::Sub4(const std::string & data)
    : Sub4()
{
    read(data);
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

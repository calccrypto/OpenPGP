#include "TagX.h"

TagX::TagX() :
    TagX(std::string())
{
}

TagX::TagX(const std::string & data) :
    Packet(),
    stream(data)
{
}

void TagX::read(std::string & data){
    stream = data;
}

std::string TagX::show() const{
    return "    " + hexlify(stream) + "\n";
}
std::string TagX::raw() const{
    return stream;
}

std::string TagX::get_stream() const{
    return stream;
}

void TagX::set_stream(const std::string & data){
    stream = data;
}

Packet::Ptr TagX::clone() const{
    return Ptr(new TagX(*this));
}

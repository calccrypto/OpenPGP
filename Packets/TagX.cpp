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

std::string TagX::show(){
    return "    " + hexlify(stream);
}
std::string TagX::raw(){
    return stream;
}

std::string TagX::get_stream(){
    return stream;
}

void TagX::set_stream(const std::string & data){
    stream = data;
}

Packet::Ptr TagX::clone() const{
    return Ptr(new TagX(*this));
}

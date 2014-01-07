#include "TagX.h"
TagX::TagX(){}

TagX::TagX(const std::string & data){
    stream = data;
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

TagX * TagX::clone(){
    return new TagX(*this);
}

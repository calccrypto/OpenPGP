#include "Tag2Sub30.h"
Tag2Sub30::Tag2Sub30(){
    type = 30;
}

Tag2Sub30::Tag2Sub30(std::string & data){
    type = 30;
    read(data);
}

void Tag2Sub30::read(std::string & data){
    flags = data[0];
    size = data.size();
}

std::string Tag2Sub30::show(){
    std::stringstream out;
    for(uint8_t bit = 0; bit < 8; bit++){
        if (flags & (1 << bit)){
            out << "            Flag - " << Features.at(1 << bit) << " (feat " << (unsigned int) (1 << bit) << ")\n";
        }
    }
    return out.str();
}

std::string Tag2Sub30::raw(){
    return std::string(1, flags);
}

Tag2Sub30 * Tag2Sub30::clone(){
    return new Tag2Sub30(*this);
}

char Tag2Sub30::get_flags(){
    return flags;
}

void Tag2Sub30::set_flags(const char f){
    flags = f;
}

#include "Tag2Sub23.h"
Tag2Sub23::Tag2Sub23(){
    type = 23;
}

Tag2Sub23::Tag2Sub23(std::string & data){
    type = 23;
    read(data);
}

void Tag2Sub23::read(std::string & data){
    flags = data[0];
    size = data.size();
}

std::string Tag2Sub23::show(){
    std::stringstream out;
    for(uint8_t bit = 0; bit < 8; bit++){
        if (flags & (1 << bit)){
            out << "            Flag - " << Key_Server_Preferences.at(1 << bit) << " (key " << (unsigned int) (1 << bit) << ")\n";
        }
    }
    return out.str();
}

std::string Tag2Sub23::raw(){
    return std::string(1, flags);
}

Tag2Sub23 * Tag2Sub23::clone(){
    return new Tag2Sub23(*this);
}

char Tag2Sub23::get_flags(){
    return flags;
}

void Tag2Sub23::set_flags(const char c){
    flags = c;
}

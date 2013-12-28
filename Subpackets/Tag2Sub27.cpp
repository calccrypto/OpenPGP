#include "Tag2Sub27.h"
Tag2Sub27::Tag2Sub27(){
    type = 27;
}

Tag2Sub27::Tag2Sub27(std::string & data){
    type = 27;
    read(data);
}

void Tag2Sub27::read(std::string & data){
    flags = data[0];
    size = data.size();
}

std::string Tag2Sub27::show(){
    std::stringstream out;
    for(uint8_t bit = 0; bit < 8; bit++){
        if (flags & (1 << bit)){
            out << "            Flag - " << Flags.at(1 << bit) << " (key " << (unsigned int) (1 << bit) << ")\n";
        }
    }
    return out.str();
}

std::string Tag2Sub27::raw(){
    return std::string(1, flags);
}

char Tag2Sub27::get_flags(){
    return flags;
}

void Tag2Sub27::set_flags(const char f){
    flags = f;
}

Tag2Sub27 * Tag2Sub27::clone(){
    return new Tag2Sub27(*this);
}

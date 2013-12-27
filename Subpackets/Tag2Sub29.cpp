#include "Tag2Sub29.h"
Tag2Sub29::Tag2Sub29(){
    type = 29;
}

Tag2Sub29::Tag2Sub29(std::string & data){
    type = 29;
    read(data);
}

void Tag2Sub29::read(std::string & data){
    code = data[0];
    reason = data.substr(1, data.size() - 1);
    size = data.size();
}

std::string Tag2Sub29::show(){
    std::stringstream out;
    out << "            Code: " << (unsigned int) code << " " << Revoke.at(code) << "\n";
    if (code){
        out << reason + "\n";
    }
    return out.str();
}

std::string Tag2Sub29::raw(){
    return std::string(1, code) + reason;
}

Tag2Sub29 * Tag2Sub29::clone(){
    return new Tag2Sub29(*this);
}

uint8_t Tag2Sub29::get_code(){
    return code;
}

std::string Tag2Sub29::get_reason(){
    return reason;
}

void Tag2Sub29::set_code(const uint8_t c){
    code = c;
}

void Tag2Sub29::set_reason(const std::string & r){
    reason = r;
}

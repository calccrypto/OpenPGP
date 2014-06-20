#include "Tag2Sub21.h"
Tag2Sub21::Tag2Sub21(){
    type = 21;
}

Tag2Sub21::Tag2Sub21(std::string & data){
    type = 21;
    read(data);
}

void Tag2Sub21::read(std::string & data){
    pha = data;
    size = data.size();
}

std::string Tag2Sub21::show(){
    std::stringstream out;
    for(unsigned int x = 0; x < pha.size(); x++){
        out << "            hash alg - " << Hash_Algorithms.at(pha[x]) << " (hash " << (unsigned int) pha[x] << ")\n";
    }
    return out.str();
}

std::string Tag2Sub21::raw(){
    return pha;
}

std::string Tag2Sub21::get_pha(){
    return pha;
}

void Tag2Sub21::set_pha(const std::string & p){
    pha = p;
}

Subpacket::Ptr Tag2Sub21::clone(){
    return Ptr(new Tag2Sub21(*this));
}

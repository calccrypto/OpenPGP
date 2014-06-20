#include "Tag9.h"
Tag9::Tag9(){
    tag = 9;
}

Tag9::Tag9(std::string & data){
    tag = 9;
    read(data);
}

void Tag9::read(std::string & data){
    size = data.size();
    encrypted_data = data;
}

std::string Tag9::show(){
    std::stringstream out;
    out << "    Encrypted Data (" << encrypted_data.size() << " octets): " << hexlify(encrypted_data) << "\n";
    return out.str();
}

std::string Tag9::raw(){
    return encrypted_data;
}

std::string Tag9::get_encrypted_data(){
    return encrypted_data;
}

void Tag9::set_encrypted_data(const std::string & e){
    encrypted_data = e;
    size = raw().size();
}

Packet::Ptr Tag9::clone(){
    return Ptr(new Tag9(*this));
}

#include "Tag18.h"
Tag18::Tag18(){
    tag = 18;
    version = 1;
}

Tag18::Tag18(std::string & data){
    tag = 18;
    version = 1;
    read(data);
}

void Tag18::read(std::string & data){
    size = data.size();
    version = data[0];
    protected_data = data.substr(1, data.size() - 1);
}

std::string Tag18::show(){
    std::stringstream out;
    out << "    Version: " << (unsigned int) version << "\n"
        << "    Encrypted Data (" << protected_data.size() << " octets): " << hexlify(protected_data) << "\n";
    return out.str();
}

std::string Tag18::raw(){
    return std::string(1, version) + protected_data;
}

std::string Tag18::get_protected_data(){
    return protected_data;
}

void Tag18::set_protected_data(const std::string & p){
    protected_data = p;
    size = raw().size();
}

Tag18 * Tag18::clone(){
    return new Tag18(*this);
}

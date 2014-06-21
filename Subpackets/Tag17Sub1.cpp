#include "Tag17Sub1.h"

unsigned int Tag17Sub1::count = 0;

Tag17Sub1::Tag17Sub1() :
    Subpacket(1),
    version(),
    encoding(),
    image()
{
    count++;
}

Tag17Sub1::Tag17Sub1(std::string & data) :
    Tag17Sub1()
{
    read(data);
}

void Tag17Sub1::read(std::string & data){
    version = data[2];
    encoding = data[3];
    image = data.substr(16, data.size() - 16); // remove image header - 12 '\x00's
}

std::string Tag17Sub1::show(){
    std::stringstream filename;
    filename << "image" << count << "." << User_Attributes.at(encoding);
    std::ofstream f(filename.str().c_str(), std::ios::binary);
    std::stringstream out;
    if (f.is_open()){
        f << image;
        f.close();
        out << "    Check working directory for " << filename.str() << " (" << image.size() << " octets).\n";
    }
    else{
        out << "    Error Writing to " << filename.str() << " (" << image.size() << " octets).\n";
    }
    return out.str();
}

std::string Tag17Sub1::raw(){
    return "\x01" + zero + "\x01\x01" + std::string(12, 0) + image;
}

std::string Tag17Sub1::get_image(){
    return image;
}

void Tag17Sub1::set_image(const std::string & i){
    image = i;
}

Subpacket::Ptr Tag17Sub1::clone() const {
    return Ptr(new Tag17Sub1(*this));
}

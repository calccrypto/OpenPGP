#include "Tag17Sub1.h"

unsigned int Tag17Sub1::count = 0;

Tag17Sub1::Tag17Sub1():
    Tag17Subpacket(1),
    version(),
    encoding(),
    image(),
    current(++count)
{}

Tag17Sub1::Tag17Sub1(std::string & data):
    Tag17Sub1()
{
    read(data);
}

void Tag17Sub1::read(std::string & data){
    version = data[2];
    encoding = data[3];
    image = data.substr(16, data.size() - 16); // remove image header - 12 '\x00's
}

std::string Tag17Sub1::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::stringstream filename;
    filename << "image" << current << "." << User_Attributes.at(encoding);
    std::ofstream f(filename.str().c_str(), std::ios::binary);
    std::stringstream out;
    out << std::string(tab, ' ') << show_title() << "\n"
        << std::string(tab, ' ');
    if (f){
        f << image;
        f.close();
        out << "    Check working directory for '";
    }
    else{
        out << "    Error writing to '";
    }
    out << filename.str() << "' (" << image.size() << " octets).";
    return out.str();
}

std::string Tag17Sub1::raw() const{
    return "\x01" + zero + "\x01\x01" + std::string(12, 0) + image;
}

std::string Tag17Sub1::get_image() const{
    return image;
}

void Tag17Sub1::set_image(const std::string & i){
    image = i;
}

Tag17Subpacket::Ptr Tag17Sub1::clone() const {
    return std::make_shared <Tag17Sub1> (*this);
}

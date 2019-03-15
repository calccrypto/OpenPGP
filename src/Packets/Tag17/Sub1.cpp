#include "Packets/Tag17/Sub1.h"

#include <fstream>

namespace OpenPGP {
namespace Subpacket {
namespace Tag17 {

unsigned int Sub1::count = 0;

void Sub1::actual_read(const std::string & data){
    if (data.size() >= 16) {
        set_version(data[2]);
        set_encoding(data[3]);
        set_image(data.substr(16, data.size() - 16)); // remove image header - 12 '\x00's
    }
}

void Sub1::show_contents(HumanReadable & hr) const{
    const decltype(Image_Attributes::NAME)::const_iterator ia_it = Image_Attributes::NAME.find(encoding);
    const std::string filename = "image" + std::to_string(current) + "." + ((ia_it == Image_Attributes::NAME.end())?"Unknown":(ia_it -> second));
    std::string out = "";
    std::ofstream f(filename, std::ios::binary);
    if (f){
        f << image;
        f.close();
        out += "Check working directory for";
    }
    else{
        out += "Error writing to";
    }

    hr << out + " '" + filename + "'.";
}

Sub1::Sub1()
    : Sub(IMAGE_ATTRIBUTE),
      version(),
      encoding(),
      image(),
      current(++count)
{}

Sub1::Sub1(const std::string & data)
    : Sub1()
{
    read(data);
}

std::string Sub1::raw() const{
    return "\x10" + zero + "\x01\x01" + std::string(12, '\x00') + image;
}

uint8_t Sub1::get_version() const{
    return version;
}

uint8_t Sub1::get_encoding() const{
    return encoding;
}

std::string Sub1::get_image() const{
    return image;
}

void Sub1::set_version(const uint8_t & v){
    version = v;
}

void Sub1::set_encoding(const uint8_t & enc){
    encoding = enc;
}

void Sub1::set_image(const std::string & i){
    image = i;
}

Sub::Ptr Sub1::clone() const{
    return std::make_shared <Sub1> (*this);
}

}
}
}

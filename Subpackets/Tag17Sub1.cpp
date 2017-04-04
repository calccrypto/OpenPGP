#include "Tag17Sub1.h"

unsigned int Tag17Sub1::count = 0;

Tag17Sub1::Tag17Sub1()
    : Tag17Subpacket(Tag17Subpacket::IMAGE_ATTRIBUTE),
      version(),
      encoding(),
      image(),
      current(++count)
{}

Tag17Sub1::Tag17Sub1(const std::string & data)
    : Tag17Sub1()
{
    read(data);
}

void Tag17Sub1::read(const std::string & data){
    version = data[2];
    encoding = data[3];
    image = data.substr(16, data.size() - 16); // remove image header - 12 '\x00's
}

std::string Tag17Sub1::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    const decltype(Image_Attributes::NAME)::const_iterator ia_it = Image_Attributes::NAME.find(encoding);
    std::string out = indent + tab + show_title() + "\n" +
                      indent;

    const std::string filename = "image" + std::to_string(current) + "." + ((ia_it == Image_Attributes::NAME.end())?"Unknown":(ia_it -> second));
    std::ofstream f(filename, std::ios::binary);
    if (f){
        f << image;
        f.close();
        out += tab + "Check working directory for";
    }
    else{
        out += tab + "Error writing to";
    }

    return out + " '" + filename + "' (" + std::to_string(image.size()) + " octets).";
}

std::string Tag17Sub1::raw() const{
    return "\x01" + zero + "\x01\x01" + std::string(12, 0) + image;
}

uint8_t Tag17Sub1::get_encoding() const{
    return encoding;
}

std::string Tag17Sub1::get_image() const{
    return image;
}

void Tag17Sub1::set_encoding(const uint8_t & enc){
    encoding = enc;
}

void Tag17Sub1::set_image(const std::string & i){
    image = i;
}

Tag17Subpacket::Ptr Tag17Sub1::clone() const{
    return std::make_shared <Tag17Sub1> (*this);
}

#include "Tag13.h"

Tag13::Tag13()
    : ID(Packet::ID::User_ID),
      contents()
{}

Tag13::Tag13(const Tag13 & copy)
    : ID(copy),
      contents(copy.contents)
{}

Tag13::Tag13(const std::string & data)
    : Tag13()
{
    read(data);
}

void Tag13::read(const std::string & data){
    size = data.size();
    contents = data;
}

std::string Tag13::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string tab = std::string(indents * indent_size, ' ');
    return tab + show_title() + "\n" +
           tab + "    User ID: " + contents;
}

std::string Tag13::raw() const{
    return contents;
}

std::string Tag13::get_contents() const{
    return contents;
}

void Tag13::set_contents(const std::string & c){
    contents = c;
    size = raw().size();
}

void Tag13::set_contents(const std::string & name, const std::string & comment, const std::string & email){
    contents = name;

    if (comment != ""){
        contents += "(" + comment + ")";
    }

    if (email != ""){
        contents += "<" + email + ">";
    }

    size = raw().size();
}

Packet::Ptr Tag13::clone() const{
    return std::make_shared <Tag13> (*this);
}

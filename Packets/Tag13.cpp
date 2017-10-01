#include "Tag13.h"

namespace OpenPGP {
namespace Packet {

Tag13::Tag13()
    : User(USER_ID),
      contents()
{}

Tag13::Tag13(const Tag13 & copy)
    : User(copy),
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

std::string Tag13::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "User ID: " + contents;
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

Tag::Ptr Tag13::clone() const{
    return std::make_shared <Packet::Tag13> (*this);
}

}
}
#include "Packets/Tag13.h"

namespace OpenPGP {
namespace Packet {

void Tag13::actual_read(const std::string & data) {
    set_contents(data);
}

void Tag13::show_contents(HumanReadable & hr) const {
    hr << "User ID: " + contents;
}

Tag13::Tag13()
    : User(USER_ID),
      contents()
{}

Tag13::Tag13(const std::string & data)
    : Tag13()
{
    read(data);
}

std::string Tag13::raw() const {
    return contents;
}

std::string Tag13::get_contents() const {
    return contents;
}

void Tag13::set_contents(const std::string & c) {
    contents = c;
}

void Tag13::set_info(const std::string & name, const std::string & comment, const std::string & email) {
    contents = name;

    if (comment != "") {
        if (contents.size()) {
            contents += " ";
        }
        contents += "(" + comment + ")";
    }

    if (email != "") {
        if (contents.size()) {
            contents += " ";
        }
        contents += "<" + email + ">";
    }
}

Tag::Ptr Tag13::clone() const {
    return std::make_shared <Packet::Tag13> (*this);
}

}
}

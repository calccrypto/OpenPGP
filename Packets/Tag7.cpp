#include "Tag7.h"

Tag7::Tag7():
    Tag5(7)
{}

Tag7::Tag7(const Tag7 & copy):
    Tag5(copy)
{}

Tag7::Tag7(std::string & data):
    Tag7()
{
    read(data);
}

Tag7::~Tag7(){}

Tag14 Tag7::get_public_obj() const{
    std::string data = raw();
    Tag14 out(data);
    out.set_tag(14);
    return out;
}

Tag14::Ptr Tag7::get_public_ptr() const{
    std::string data = raw();
    Tag14::Ptr out(new Tag14(data));
    out -> set_tag(14);
    return out;
}

Packet::Ptr Tag7::clone() const{
    Ptr out = std::make_shared <Tag7> (*this);
    out -> s2k = s2k -> clone();
    return out;
}

Tag7 & Tag7::operator=(const Tag7 & copy){
    Tag5::operator =(copy);
    return *this;
}

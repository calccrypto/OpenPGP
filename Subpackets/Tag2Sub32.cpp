#include "Tag2Sub32.h"
Tag2Sub32::Tag2Sub32(){
    type = 32;
}

Tag2Sub32::Tag2Sub32(const Tag2Sub32 & tag2sub32){
    type = tag2sub32.type;
    size = tag2sub32.size;
    embedded = std::dynamic_pointer_cast<Tag2>(tag2sub32.embedded -> clone());
}

Tag2Sub32::Tag2Sub32(std::string & data){
    type = 32;
    read(data);
}

Tag2Sub32::~Tag2Sub32(){
}

void Tag2Sub32::read(std::string & data){
    embedded = std::make_shared<Tag2>();
    embedded -> read(data);
    size = data.size();
}

std::string Tag2Sub32::show(){
    return embedded -> show();
}

std::string Tag2Sub32::raw(){
    return embedded -> raw();
}

Tag2::Ptr Tag2Sub32::get_embedded(){
    return embedded;
}

void Tag2Sub32::set_embedded(Tag2::Ptr e){
    embedded = std::dynamic_pointer_cast<Tag2>(e -> clone());
}

Subpacket::Ptr Tag2Sub32::clone(){
    return Ptr(new Tag2Sub32(*this));
}

Tag2Sub32 Tag2Sub32::operator=(const Tag2Sub32 & tag2sub32){
    type = tag2sub32.type;
    size = tag2sub32.size;
    embedded = std::dynamic_pointer_cast<Tag2>(tag2sub32.embedded -> clone());
    return *this;
}

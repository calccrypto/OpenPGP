#include "Tag14.h"
Tag14::Tag14(){
    tag = 14;
}

Tag14::Tag14(std::string & data){
    tag = 14;
    read(data);
}

Tag14 * Tag14::clone(){
    return new Tag14(*this);
}

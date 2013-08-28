#include "Tag7.h"
Tag7::Tag7(){
    tag = 7;
}

Tag7::Tag7(std::string & data){
    tag = 7;
    read(data);
}

Tag7 * Tag7::clone(){
    return new Tag7(*this);
}

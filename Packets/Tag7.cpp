#include "Tag7.h"
Tag7::Tag7(){
    tag = 7;
}

Tag7::Tag7(std::string & data){
    tag = 7;
    read(data);
}

Tag7 * Tag7::clone(){
    Tag7 * out = new Tag7(*this);
    out -> s2k = s2k -> clone();
    return out;
}

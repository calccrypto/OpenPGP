#include "Tag7.h"
Tag7::Tag7(){
    tag = 7;
    s2k = NULL;
}

Tag7::Tag7(const Tag7 & tag7){
    tag = tag7.tag;
    version = tag7.version;
    format = tag7.format;
    size = tag7.size;
    time = tag7.time;
    pka = tag7.pka;
    mpi = tag7.mpi;
    expire = tag7.expire;
    s2k_con = tag7.s2k_con;
    sym = tag7.sym;
    s2k = tag7.s2k -> clone();
    IV = tag7.IV;
    secret = tag7.secret;
}

Tag7::Tag7(std::string & data){
    tag = 7;
    s2k = NULL;
    read(data);
}

Tag7::~Tag7(){
    delete s2k;
    s2k = NULL;
}

Tag7 * Tag7::clone(){
    Tag7 * out = new Tag7(*this);
    out -> s2k = s2k -> clone();
    return out;
}

Tag7 Tag7::operator=(const Tag7 & tag7){
    tag = tag7.tag;
    version = tag7.version;
    format = tag7.format;
    size = tag7.size;
    time = tag7.time;
    pka = tag7.pka;
    mpi = tag7.mpi;
    expire = tag7.expire;
    s2k_con = tag7.s2k_con;
    sym = tag7.sym;
    s2k = tag7.s2k -> clone();
    IV = tag7.IV;
    secret = tag7.secret;
    return *this;
}

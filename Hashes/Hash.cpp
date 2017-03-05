#include "./Hash.h"

HashAlg::HashAlg() :
    stack(),
    clen(0)
{}

HashAlg::~HashAlg(){
    stack.clear();
    clen = 0;
}

std::string HashAlg::digest(){
    return unhexlify(hexdigest());
}

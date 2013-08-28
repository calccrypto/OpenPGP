#include "Hash.h"

Hash::Hash(){}

void Hash::update(const std::string & str){
    total += str;
    run();
}

std::string Hash::digest(){
    return unhexlify(hexdigest());
}

#include "./Hash.h"

Hash::Hash(){}

std::string Hash::digest(){
    return unhexlify(hexdigest());
}

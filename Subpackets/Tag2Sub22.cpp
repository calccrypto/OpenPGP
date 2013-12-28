#include "Tag2Sub22.h"
Tag2Sub22::Tag2Sub22(){
    type = 22;
}

Tag2Sub22::Tag2Sub22(std::string & data){
    type = 22;
    read(data);
}

void Tag2Sub22::read(std::string & data){
    pca = data;
    size = data.size();
}

std::string Tag2Sub22::show(){
    std::stringstream out;
    for(unsigned int x = 0; x < pca.size(); x++){
        out << "            comp alg - " << Compression_Algorithms.at(pca[x]) << " (comp " << (unsigned int) pca[x] << ")\n";
    }
    return out.str();
}

std::string Tag2Sub22::raw(){
    return pca;
}

std::string Tag2Sub22::get_pca(){
    return pca;
}

void Tag2Sub22::set_pca(const std::string & c){
    pca = c;
}

Tag2Sub22 * Tag2Sub22::clone(){
    return new Tag2Sub22(*this);
}

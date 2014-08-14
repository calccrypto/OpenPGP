#include "PGPDetachedSignature.h"

PGPDetachedSignature::PGPDetachedSignature():
    PGP()
{
    ASCII_Armor = 5;
}

PGPDetachedSignature::PGPDetachedSignature(const PGPDetachedSignature & copy):
    PGP(copy)
{
    if ((ASCII_Armor == 255) && meaningful()){
        ASCII_Armor = 5;
    }
}

PGPDetachedSignature::PGPDetachedSignature(std::string & data):
    PGP(data)
{
    if ((ASCII_Armor == 255) && meaningful()){
        ASCII_Armor = 5;
    }
}

PGPDetachedSignature::PGPDetachedSignature(std::ifstream & f):
    PGP(f)
{
    if ((ASCII_Armor == 255) && meaningful()){
        ASCII_Armor = 5;
    }
}

PGPDetachedSignature::~PGPDetachedSignature(){}

PGP::Ptr PGPDetachedSignature::clone() const{
    return std::make_shared <PGPDetachedSignature> (*this);
}

bool PGPDetachedSignature::meaningful() const{
    return ((packets.size() == 1) && (packets[0] -> get_tag() == 2));
}

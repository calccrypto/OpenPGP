#include "PGPDetachedSignature.h"

PGPDetachedSignature::PGPDetachedSignature():
    PGP()
{}

PGPDetachedSignature::PGPDetachedSignature(const PGPDetachedSignature & copy):
    PGP(copy)
{}

PGPDetachedSignature::PGPDetachedSignature(std::string & data):
    PGP(data)
{}

PGPDetachedSignature::PGPDetachedSignature(std::ifstream & f):
    PGP(f)
{}

PGPDetachedSignature::~PGPDetachedSignature(){}

PGP::Ptr PGPDetachedSignature::clone() const{
    PGPDetachedSignature::Ptr out(new PGPDetachedSignature(*this));
    // out -> ASCII_Armor = ASCII_Armor;
    // out -> Armor_Header = Armor_Header;
    // out -> packets = get_packets_clone();
    return out;
}

bool PGPDetachedSignature::meaningful() const{
    return ((packets.size() == 1) && (packets[0] -> get_tag() == 2));
}

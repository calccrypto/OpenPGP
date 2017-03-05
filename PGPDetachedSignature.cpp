#include "PGPDetachedSignature.h"

PGPDetachedSignature::PGPDetachedSignature()
    : PGP()
{
    type = PGP::Type::SIGNATURE;
}

PGPDetachedSignature::PGPDetachedSignature(const PGPDetachedSignature & copy)
    : PGP(copy)
{
    if ((type == PGP::Type::UNKNOWN) && meaningful()){
        type = PGP::Type::SIGNATURE;
    }
}

PGPDetachedSignature::PGPDetachedSignature(const std::string & data)
    : PGP(data)
{
    if ((type == PGP::Type::UNKNOWN) && meaningful()){
        type = PGP::Type::SIGNATURE;
    }
}

PGPDetachedSignature::PGPDetachedSignature(std::istream & stream)
    : PGP(stream)
{
    if ((type == PGP::Type::UNKNOWN) && meaningful()){
        type = PGP::Type::SIGNATURE;
    }
}

PGPDetachedSignature::~PGPDetachedSignature(){}

bool PGPDetachedSignature::meaningful() const{
    return ((packets.size() == 1) && (packets[0] -> get_tag() == Packet::ID::Signature));
}

PGP::Ptr PGPDetachedSignature::clone() const{
    return std::make_shared <PGPDetachedSignature> (*this);
}

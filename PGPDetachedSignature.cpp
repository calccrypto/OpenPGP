#include "PGPDetachedSignature.h"

PGPDetachedSignature::PGPDetachedSignature()
    : PGP()
{
    type = PGP::Type::SIGNATURE;
}

PGPDetachedSignature::PGPDetachedSignature(const PGP & copy)
    : PGP(copy)
{}

PGPDetachedSignature::PGPDetachedSignature(const PGPDetachedSignature & copy)
    : PGP(copy)
{}

PGPDetachedSignature::PGPDetachedSignature(const std::string & data)
    : PGP(data)
{}

PGPDetachedSignature::PGPDetachedSignature(std::istream & stream)
    : PGP(stream)
{}

PGPDetachedSignature::~PGPDetachedSignature(){}

bool PGPDetachedSignature::meaningful(std::string & error) const{
    return ((type == PGP::Type::SIGNATURE) && PGP::meaningful_SIGNATURE(error));
}

PGP::Ptr PGPDetachedSignature::clone() const{
    return std::make_shared <PGPDetachedSignature> (*this);
}

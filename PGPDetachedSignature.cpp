#include "PGPDetachedSignature.h"

PGPDetachedSignature::PGPDetachedSignature()
    : PGP()
{
    type = PGP::Type::SIGNATURE;
}

PGPDetachedSignature::PGPDetachedSignature(const PGPDetachedSignature & copy)
    : PGP(copy)
{
    std::string error;
    if (!meaningful(error)){
        std::cerr << error << std::endl;
    }
    else{
        type = PGP::Type::SIGNATURE;
    }
}

PGPDetachedSignature::PGPDetachedSignature(const std::string & data)
    : PGP(data)
{
    std::string error;
    if (!meaningful(error)){
        std::cerr << error << std::endl;
    }
    else{
        type = PGP::Type::SIGNATURE;
    }
}

PGPDetachedSignature::PGPDetachedSignature(std::istream & stream)
    : PGP(stream)
{
    std::string error;
    if (!meaningful(error)){
        std::cerr << error << std::endl;
    }
    else{
        type = PGP::Type::SIGNATURE;
    }
}

PGPDetachedSignature::~PGPDetachedSignature(){}

bool PGPDetachedSignature::meaningful(std::string & error) const{
    if (packets.size() != 1){
        error = "Warning: Too many packets";
        return false;
    }

    if (packets[0] -> get_tag() == Packet::ID::Signature){
        error = "Warning: Packet is not a signature packet";
        return false;
    }

    return true;
}

bool PGPDetachedSignature::meaningful() const{
    return ((packets.size() == 1) && (packets[0] -> get_tag() == Packet::ID::Signature));
}

PGP::Ptr PGPDetachedSignature::clone() const{
    return std::make_shared <PGPDetachedSignature> (*this);
}

#include "PGPDetachedSignature.h"

PGPDetachedSignature::PGPDetachedSignature()
    : PGP()
{
    type = SIGNATURE;
}

PGPDetachedSignature::PGPDetachedSignature(const PGP & copy)
    : PGP(copy)
{}

PGPDetachedSignature::PGPDetachedSignature(const PGPDetachedSignature & copy)
    : PGP(copy)
{
    type = SIGNATURE;
}

PGPDetachedSignature::PGPDetachedSignature(const std::string & data)
    : PGP(data)
{
    type = SIGNATURE;

    // warn if packet sequence is not meaningful
    if (!meaningful()){
        throw std::runtime_error("Error: Data does not form a meaningful PGP Detached Signature");
    }
}

PGPDetachedSignature::PGPDetachedSignature(std::istream & stream)
    : PGP(stream)
{
    type = SIGNATURE;

    // warn if packet sequence is not meaningful
    if (!meaningful()){
        throw std::runtime_error("Error: Data does not form a meaningful PGP Detached Signature");
    }
}

PGPDetachedSignature::~PGPDetachedSignature(){}

bool PGPDetachedSignature::meaningful(const PGP & pgp){
    if (pgp.get_type() != SIGNATURE){
        // "Error: ASCII Armor type is not SIGNATURE.\n";
        return false;
    }

    if (pgp.get_packets().size() != 1){
        // "Error: Wrong number of packets.\n";
        return false;
    }

    // if (pgp.get_packets()[0] -> get_tag() != Packet::SIGNATURE){
        // // "Error: Packet is not a signature packet.\n";
        // return false;
    // }

    // if (!Signature_Type::is_signed_document(std::static_pointer_cast <Tag2> (pgp.get_packets()[0]) -> get_type())){
        // // "Error: Signature type is not over a document.\n";
        // return false;
    // }

    return true;
}

bool PGPDetachedSignature::meaningful() const{
    return meaningful(*this);
}

PGP::Ptr PGPDetachedSignature::clone() const{
    return std::make_shared <PGPDetachedSignature> (*this);
}

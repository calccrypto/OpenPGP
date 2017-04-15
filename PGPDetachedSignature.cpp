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
    std::string error;
    if (!meaningful(error)){
        std::cerr << error << std::endl;
    }
}

PGPDetachedSignature::PGPDetachedSignature(std::istream & stream)
    : PGP(stream)
{
    type = SIGNATURE;

    // warn if packet sequence is not meaningful
    std::string error;
    if (!meaningful(error)){
        std::cerr << error << std::endl;
    }
}

PGPDetachedSignature::~PGPDetachedSignature(){}

bool PGPDetachedSignature::meaningful(const PGP & pgp, std::string & error){
    if (pgp.get_type() != SIGNATURE){
        error += "Error: ASCII Armor type is not SIGNATURE.\n";
        return false;
    }

    if (pgp.get_packets().size() != 1){
        error += "Error: Wrong number of packets.\n";
        return false;
    }

    // if (pgp.get_packets()[0] -> get_tag() != Packet::SIGNATURE){
        // error += "Error: Packet is not a signature packet.\n";
        // return false;
    // }

    // if (!Signature_Type::is_signed_document(std::static_pointer_cast <Tag2> (pgp.get_packets()[0]) -> get_type())){
        // error += "Error: Signature type is not over a document.\n";
        // return false;
    // }

    return true;
}

bool PGPDetachedSignature::meaningful(std::string & error) const{
    return meaningful(*this, error);
}

PGP::Ptr PGPDetachedSignature::clone() const{
    return std::make_shared <PGPDetachedSignature> (*this);
}

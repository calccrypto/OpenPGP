#include "DetachedSignature.h"

namespace OpenPGP {

DetachedSignature::DetachedSignature()
    : PGP()
{
    type = SIGNATURE;
}

DetachedSignature::DetachedSignature(const PGP & copy)
    : PGP(copy)
{}

DetachedSignature::DetachedSignature(const DetachedSignature & copy)
    : PGP(copy)
{
    type = SIGNATURE;
}

DetachedSignature::DetachedSignature(const std::string & data)
    : PGP(data)
{
    type = SIGNATURE;

    // warn if packet sequence is not meaningful
    if (!meaningful()){
        throw std::runtime_error("Error: Data does not form a meaningful PGP Detached Signature");
    }
}

DetachedSignature::DetachedSignature(std::istream & stream)
    : PGP(stream)
{
    type = SIGNATURE;

    // warn if packet sequence is not meaningful
    if (!meaningful()){
        throw std::runtime_error("Error: Data does not form a meaningful PGP Detached Signature");
    }
}

DetachedSignature::~DetachedSignature(){}

bool DetachedSignature::meaningful(const PGP & pgp){
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

    // if (!Signature_Type::is_signed_document(std::static_pointer_cast <Packet::Tag2> (pgp.get_packets()[0]) -> get_type())){
        // // "Error: Signature type is not over a document.\n";
        // return false;
    // }

    return true;
}

bool DetachedSignature::meaningful() const{
    return meaningful(*this);
}

PGP::Ptr DetachedSignature::clone() const{
    return std::make_shared <DetachedSignature> (*this);
}

}

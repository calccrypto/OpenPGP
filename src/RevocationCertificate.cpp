#include "RevocationCertificate.h"

namespace OpenPGP {

RevocationCertificate::RevocationCertificate()
    : PGP()
{
    type = PUBLIC_KEY_BLOCK;
}

RevocationCertificate::RevocationCertificate(const PGP & copy)
    : PGP(copy)
{}

RevocationCertificate::RevocationCertificate(const RevocationCertificate & copy)
    : PGP(copy)
{}

RevocationCertificate::RevocationCertificate(const std::string & data)
    : PGP(data)
{
    type = PUBLIC_KEY_BLOCK;

    // warn if packet sequence is not meaningful
    if (!meaningful()){
        throw std::runtime_error("Error: Data does not form a meaningful PGP Revocation Certificate");
    }
}

RevocationCertificate::RevocationCertificate(std::istream & stream)
    : PGP(stream)
{
    type = PUBLIC_KEY_BLOCK;

    // warn if packet sequence is not meaningful
    if (!meaningful()){
        throw std::runtime_error("Error: Data does not form a meaningful PGP Revocation Certificate");
    }
}

RevocationCertificate::~RevocationCertificate(){}

uint8_t RevocationCertificate::get_revoke_type() const{
    if (!meaningful()){
        throw std::runtime_error("Error: Bad Revocation Certificate.");
    }

    return std::static_pointer_cast <Packet::Tag2> (packets[0]) -> get_type();
}

bool RevocationCertificate::meaningful(const PGP & pgp){
    if (pgp.get_type() != PUBLIC_KEY_BLOCK){
        // "Error: ASCII Armor type is not PUBLIC_KEY_BLOCK.\n";
        return false;
    }

    if (pgp.get_packets().size() != 1){
        // "Error: Wrong number of packets.\n";
        return false;
    }

    if (pgp.get_packets()[0] -> get_tag() != Packet::SIGNATURE){
        // "Error: Packet is not a signature packet.\n";
        return false;
    }

    if (!Signature_Type::is_revocation(std::static_pointer_cast <Packet::Tag2> (pgp.get_packets()[0]) -> get_type())){
        // "Error: Signature packet does not contain a revocation certificate.\n";
        return false;
    }

    return true;
}

bool RevocationCertificate::meaningful() const{
    return meaningful(*this);
}

PGP::Ptr RevocationCertificate::clone() const{
    return std::make_shared <RevocationCertificate> (*this);
}

}

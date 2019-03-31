#include "Packets/Tag6.h"

namespace OpenPGP {
namespace Packet {

Status Tag6::actual_valid(const bool check_mpi) const {
    if (version == 3) {
        if (!PKA::is_RSA(pka)) {
            return Status::PKA_CANNOT_BE_USED;
        }

        if (check_mpi) {
            if (mpi.size() != 2) {
                return Status::INVALID_MPI_COUNT;
            }
        }
    }
    else if (version == 4) {
        if (!PKA::valid(pka)) {
            return Status::INVALID_PUBLIC_KEY_ALGORITHM;
        }

        if (check_mpi) {
            bool valid_mpi = false;
            switch (pka) {
                case PKA::ID::RSA_ENCRYPT_OR_SIGN:
                case PKA::ID::RSA_ENCRYPT_ONLY:
                case PKA::ID::RSA_SIGN_ONLY:
                    valid_mpi = (mpi.size() == 2);
                    break;
                case PKA::ID::DSA:
                    valid_mpi = (mpi.size() == 4);
                    break;
                case PKA::ID::ELGAMAL:
                    valid_mpi = (mpi.size() == 3);
                    break;
                default:
                    break;
            }

            if (!valid_mpi) {
                return Status::INVALID_MPI_COUNT;
            }
        }
    }
    else {
        return Status::INVALID_VERSION;
    }

    return Status::SUCCESS;
}

Tag6::Tag6(const uint8_t tag)
    : Key(tag)
{}

Tag6::Tag6()
    : Tag6(PUBLIC_KEY)
{}

Tag6::Tag6(const std::string & data)
    : Tag6(PUBLIC_KEY)
{
    read(data);
}

Tag6::~Tag6() {}

Tag::Ptr Tag6::clone() const {
    return std::make_shared <Packet::Tag6> (*this);
}

}
}

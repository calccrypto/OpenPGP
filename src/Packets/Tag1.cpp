#include "Packets/Tag1.h"

namespace OpenPGP {
namespace Packet {

void Tag1::actual_read(const std::string & data, std::string::size_type & pos, const std::string::size_type & length) {
    set_version(data[pos + 0]);
    set_keyid(data.substr(pos + 1, 8));
    set_pka(data[pos + 9]);
    pos += 10;
    while (pos < length) {
        mpi.push_back(read_MPI(data, pos));
    }
}

void Tag1::show_contents(HumanReadable & hr) const {
    hr << "Version: " + std::to_string(version)
       << "KeyID: " + hexlify(keyid)
       << "Public Key Algorithm: " + get_mapped(PKA::NAME, pka) + " (pka " + std::to_string(pka) + ")";
    if (pka <= PKA::ID::RSA_SIGN_ONLY) {
        hr << "RSA m**e mod n (" + std::to_string(bitsize(mpi[0])) + " bits): " + mpitohex(mpi[0]);
    }
    else if (pka == PKA::ID::ELGAMAL) {
        hr << "ELGAMAL g**k mod p (" + std::to_string(bitsize(mpi[0])) + " bits): " + mpitohex(mpi[0])
           << "ELGAMAL m * y**k mod p (" + std::to_string(bitsize(mpi[1])) + " bits): " + mpitohex(mpi[1]);
    }
}

std::string Tag1::actual_raw() const {
    std::string out = "\x03" + keyid + std::string(1, pka);
    for(unsigned int x = 0; x < mpi.size(); x++) {
        out += write_MPI(mpi[x]);
    }
    return out;
}

Status Tag1::actual_valid(const bool check_mpi) const {
    if (version != 3) {
        return Status::INVALID_VERSION;
    }

    if (keyid.size() != 8) {
        return Status::INVALID_LENGTH;
    }

    if (!PKA::valid(pka)) {
        return Status::INVALID_PUBLIC_KEY_ALGORITHM;
    }

    if (!PKA::can_encrypt(pka)) {
        return Status::PKA_CANNOT_BE_USED;
    }

    if (check_mpi) {
        bool valid_mpi = false;
        switch (pka) {
            case PKA::ID::RSA_ENCRYPT_OR_SIGN:
            case PKA::ID::RSA_ENCRYPT_ONLY:
                valid_mpi = (mpi.size() == 1);
                break;
            case PKA::ID::ELGAMAL:
                valid_mpi = (mpi.size() == 2);
                break;
            #ifdef GPG_COMPATIBLE
            case PKA::ID::ECDH:
                valid_mpi = (mpi.size() == 1);
                break;
            #endif
            default:
                break;
        }

        if (!valid_mpi) {
            return Status::INVALID_MPI_COUNT;
        }
    }

    return Status::SUCCESS;
}

Tag1::Tag1()
    : Tag(PUBLIC_KEY_ENCRYPTED_SESSION_KEY, 3),
      keyid(),
      pka(),
      mpi()
{}

Tag1::Tag1(const std::string & data)
    : Tag1()
{
    read(data);
}

std::string Tag1::get_keyid() const {
    return keyid;
}

uint8_t Tag1::get_pka() const {
    return pka;
}

PKA::Values Tag1::get_mpi() const {
    return mpi;
}

void Tag1::set_keyid(const std::string & k) {
    keyid = k;
}

void Tag1::set_pka(const uint8_t p) {
    pka = p;
}

void Tag1::set_mpi(const PKA::Values & m) {
    mpi = m;
}

Tag::Ptr Tag1::clone() const {
    return std::make_shared <Packet::Tag1> (*this);
}

}
}

#include "Packets/Tag1.h"

namespace OpenPGP {
namespace Packet {

void Tag1::actual_read(const std::string & data) {
    set_version(data[0]);
    set_keyid(data.substr(1, 8));
    set_pka(data[9]);
    std::string::size_type pos = 10;
    while (pos < data.size()) {
        mpi.push_back(read_MPI(data, pos));
    }
}

void Tag1::show_contents(HumanReadable & hr) const {
    const decltype(PKA::NAME)::const_iterator pka_it = PKA::NAME.find(pka);
    hr << "Version: " + std::to_string(version)
       << "KeyID: " + hexlify(keyid)
       << "Public Key Algorithm: " + ((pka_it == PKA::NAME.end())?"Unknown":(pka_it -> second)) + " (pka " + std::to_string(pka) + ")";
    if (pka <= PKA::ID::RSA_SIGN_ONLY) {
        hr << "RSA m**e mod n (" + std::to_string(bitsize(mpi[0])) + " bits): " + mpitohex(mpi[0]);
    }
    else if (pka == PKA::ID::ELGAMAL) {
        hr << "ELGAMAL g**k mod p (" + std::to_string(bitsize(mpi[0])) + " bits): " + mpitohex(mpi[0])
           << "ELGAMAL m * y**k mod p (" + std::to_string(bitsize(mpi[1])) + " bits): " + mpitohex(mpi[1]);
    }
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

std::string Tag1::raw() const {
    std::string out = "\x03" + keyid + std::string(1, pka);
    for(unsigned int x = 0; x < mpi.size(); x++) {
        out += write_MPI(mpi[x]);
    }
    return out;
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

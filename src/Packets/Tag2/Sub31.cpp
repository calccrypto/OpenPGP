#include "Packets/Tag2/Sub31.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub31::actual_read(const std::string & data) {
    if (data.size() > 2) {
        set_pka(data[0]);
        set_hash_alg(data[1]);
        set_hash(data.substr(2, data.size() - 2));
    }
}

void Sub31::show_contents(HumanReadable & hr) const {
    hr << "Public Key Algorithm: " + get_mapped(PKA::NAME, pka) + " (pka " + std::to_string(pka) + ")"
       << "Hash Algorithm: " + get_mapped(Hash::NAME, hash_alg) + " (hash " + std::to_string(hash_alg) + ")"
       << "Hash: " + hexlify(hash);
}

Status Sub31::actual_valid(const bool) const {
    if (PKA::NAME.find(pka) == PKA::NAME.end()) {
        return Status::INVALID_PUBLIC_KEY_ALGORITHM;
    }

    if (Hash::NAME.find(hash_alg) == Hash::NAME.end()) {
        return Status::INVALID_HASH_ALGORITHM;
    }

    if ((Hash::LENGTH.at(hash_alg) >> 3) != hash.size()) {
        return Status::INVALID_LENGTH;
    }

    return Status::SUCCESS;
}

Sub31::Sub31()
    : Sub(SIGNATURE_TARGET),
      pka(), hash_alg(),
      hash()
{}

Sub31::Sub31(const std::string & data)
    : Sub31()
{
    read(data);
}

std::string Sub31::raw() const {
    return std::string(1, pka) + std::string(1, hash_alg) + hash;
}

uint8_t Sub31::get_pka() const {
    return pka;
}

uint8_t Sub31::get_hash_alg() const {
    return hash_alg;
}

std::string Sub31::get_hash() const {
    return hash;
}

void Sub31::set_pka(const uint8_t p) {
    pka = p;
}

void Sub31::set_hash_alg(const uint8_t h) {
    hash_alg = h;
}

void Sub31::set_hash(const std::string & h) {
    hash = h;
}

Sub::Ptr Sub31::clone() const {
    return std::make_shared <Sub31> (*this);
}

}
}
}

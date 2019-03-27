#include "Packets/Tag4.h"

namespace OpenPGP {
namespace Packet {

void Tag4::actual_read(const std::string & data, std::string::size_type & pos, const std::string::size_type &) {
    set_version(data[pos + 0]); // 3
    set_type   (data[pos + 1]);
    set_hash   (data[pos + 2]);
    set_pka    (data[pos + 3]);
    set_keyid  (data.substr(pos + 4, 8));
    set_last   (data[pos + 12]);
    pos += 13;
}

void Tag4::show_contents(HumanReadable & hr) const {
    hr << "Version: " + std::to_string(version)
       << "Signature Type: " + get_mapped(Signature_Type::NAME, type) + " (sig " + std::to_string(type) + ")"
       << "Hash Algorithm: " + get_mapped(Hash::NAME, hash) + " (hash " + std::to_string(hash) + ")"
       << "Public Key Algorithm: " + get_mapped(PKA::NAME, pka)  + " (pka " + std::to_string(pka) + ")"
       << "KeyID: " + hexlify(keyid)
       << "Last: " + std::to_string(last);
}

std::string Tag4::actual_raw() const {
    return "\x03" + std::string(1, type) + std::string(1, hash) + std::string(1, pka) + keyid + std::string(1, last);
}

Error Tag4::actual_valid(const bool) const {
    if (version != 3) {
        return Error::INVALID_VERSION;
    }

    if (!Signature_Type::valid(type)) {
        return Error::INVALID_SIGNATURE_TYPE;
    }

    if (!Hash::valid(hash)) {
        return Error::INVALID_HASH_ALGORITHM;
    }

    if (!PKA::valid(pka)) {
        return Error::INVALID_PUBLIC_KEY_ALGORITHM;
    }

    if (keyid.size() != 8) {
        return Error::INVALID_LENGTH;
    }

    return Error::SUCCESS;
}

Tag4::Tag4()
    : Tag(ONE_PASS_SIGNATURE, 3),
      type(), hash(), pka(),
      keyid(),
      last(1)
{}

Tag4::Tag4(const std::string & data)
    : Tag4()
{
    read(data);
}

uint8_t Tag4::get_type() const {
    return type;
}

uint8_t Tag4::get_hash() const {
    return hash;
}

uint8_t Tag4::get_pka() const {
    return pka;
}

std::string Tag4::get_keyid() const {
    return keyid;
}

uint8_t Tag4::get_last() const {
    return last;
}

void Tag4::set_type(const uint8_t t) {
    type = t;
}

void Tag4::set_hash(const uint8_t h) {
    hash = h;
}

void Tag4::set_pka(const uint8_t p) {
    pka = p;
}

void Tag4::set_keyid(const std::string & k) {
    if (k.size() != 8) {
        throw std::runtime_error("Error: Key ID must be 8 octets.");
    }
    keyid = k;
}

void Tag4::set_last(const uint8_t n) {
    last = n;
}

Tag::Ptr Tag4::clone() const {
    return std::make_shared <Packet::Tag4> (*this);
}

}
}

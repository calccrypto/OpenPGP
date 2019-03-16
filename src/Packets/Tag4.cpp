#include "Packets/Tag4.h"

namespace OpenPGP {
namespace Packet {

void Tag4::actual_read(const std::string & data) {
    set_version(data[0]); // 3
    set_type   (data[1]);
    set_hash   (data[2]);
    set_pka    (data[3]);
    set_keyid  (data.substr(4, 8));
    set_last   (data[12]);
}

void Tag4::show_contents(HumanReadable & hr) const {
    const decltype(Signature_Type::NAME)::const_iterator sigtype_it = Signature_Type::NAME.find(type);
    const decltype(Hash::NAME)::const_iterator hash_it = Hash::NAME.find(hash);
    const decltype(PKA::NAME)::const_iterator pka_it = PKA::NAME.find(pka);
    hr << "Version: " + std::to_string(version)
       << "Signature Type: " + ((sigtype_it == Signature_Type::NAME.end())?"Unknown":(sigtype_it -> second))+ " (sig " + std::to_string(type) + ")"
       << "Hash Algorithm: " + ((hash_it == Hash::NAME.end())?"Unknown":(hash_it -> second)) + " (hash " + std::to_string(hash) + ")"
       << "Public Key Algorithm: " + ((pka_it == PKA::NAME.end())?"Unknown":(pka_it -> second))  + " (pka " + std::to_string(pka) + ")"
       << "KeyID: " + hexlify(keyid)
       << "Last: " + std::to_string(last);
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

std::string Tag4::raw() const {
    return "\x03" + std::string(1, type) + std::string(1, hash) + std::string(1, pka) + keyid + std::string(1, last);
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

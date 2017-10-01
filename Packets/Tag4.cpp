#include "Tag4.h"

namespace OpenPGP {
namespace Packet {

Tag4::Tag4()
    : Tag(ONE_PASS_SIGNATURE, 3),
      type(), hash(), pka(),
      keyid(),
      nested(1)
{}

Tag4::Tag4(const Tag4 & copy)
    : Tag(copy)
{
    type = copy.type;
    hash = copy.hash;
    pka = copy.pka;
    keyid = copy.keyid;
    nested = copy.nested;
}

Tag4::Tag4(const std::string & data)
    : Tag4()
{
    read(data);
}

void Tag4::read(const std::string & data){
    size    = data.size();
    version = data[0];                  // 3
    type    = data[1];
    hash    = data[2];
    pka     = data[3];
    keyid   = data.substr(4, 8);
    nested  = data[12];
}

std::string Tag4::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    const decltype(Signature_Type::NAME)::const_iterator sigtype_it = Signature_Type::NAME.find(type);
    const decltype(Hash::NAME)::const_iterator hash_it = Hash::NAME.find(hash);
    const decltype(PKA::NAME)::const_iterator pka_it = PKA::NAME.find(pka);
    return indent + show_title() + "\n" +
           indent + tab + "Version: " + std::to_string(version) + "\n" +
           indent + tab + "Signature Type: " + ((sigtype_it == Signature_Type::NAME.end())?"Unknown":(sigtype_it -> second))+ " (sig " + std::to_string(type) + ")\n" +
           indent + tab + "Hash Algorithm: " + ((hash_it == Hash::NAME.end())?"Unknown":(hash_it -> second)) + " (hash " + std::to_string(hash) + ")\n" +
           indent + tab + "Public Key Algorithm: " + ((pka_it == PKA::NAME.end())?"Unknown":(pka_it -> second))  + " (pka " + std::to_string(pka) + ")\n" +
           indent + tab + "KeyID: " + hexlify(keyid) + "\n" +
           indent + tab + "Nested: " + std::to_string(nested);
    }

std::string Tag4::raw() const{
    return "\x03" + std::string(1, type) + std::string(1, hash) + std::string(1, pka) + keyid + std::string(1, nested);
}

uint8_t Tag4::get_type() const{
    return type;
}

uint8_t Tag4::get_hash() const{
    return hash;
}

uint8_t Tag4::get_pka() const{
    return pka;
}

std::string Tag4::get_keyid() const{
    return keyid;
}

uint8_t Tag4::get_nested() const{
    return nested;
}

void Tag4::set_type(const uint8_t t){
    type = t;
    size = raw().size();
}

void Tag4::set_hash(const uint8_t h){
    hash = h;
    size = raw().size();
}

void Tag4::set_pka(const uint8_t p){
    pka = p;
    size = raw().size();
}

void Tag4::set_keyid(const std::string & k){
    if (k.size() != 8){
        throw std::runtime_error("Error: Key ID must be 8 octets.");
    }
    keyid = k;
    size = raw().size();
}

void Tag4::set_nested(const uint8_t n){
    nested = n;
    size = raw().size();
}

Tag::Ptr Tag4::clone() const{
    return std::make_shared <Packet::Tag4> (*this);
}

}
}
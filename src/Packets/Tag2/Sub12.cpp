#include "Packets/Tag2/Sub12.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub12::actual_read(const std::string & data) {
    if (data.size() >= 22) {
        set_class(data[0]);
        set_pka(data[1]);
        set_fingerprint(data.substr(2, 20));
    }
}

void Sub12::show_contents(HumanReadable & hr) const {
    hr << std::string("Class: ") + std::to_string(_class)
       << std::string("Public Key Algorithm: ") + get_mapped(PKA::NAME, (uint8_t) pka) + " (pka " + std::to_string(pka) + ")"
       << std::string("Fingerprint: ") + fingerprint;
}

Sub12::Sub12()
    : Sub(REVOCATION_KEY),
      _class(),
      pka(),
      fingerprint()
{}

Sub12::Sub12(const std::string & data)
    : Sub12()
{
    read(data);
}

std::string Sub12::raw() const {
    return std::string(1, _class) + std::string(1, pka) + fingerprint;
}

uint8_t Sub12::get_class() const {
    return _class;
}

uint8_t Sub12::get_pka() const {
    return pka;
}

std::string Sub12::get_fingerprint() const {
    return fingerprint;
}

void Sub12::set_class(const uint8_t c) {
    _class = c;
}

void Sub12::set_pka(const uint8_t p) {
    pka = p;
}

void Sub12::set_fingerprint(const std::string & f) {
    fingerprint = f;
}

Sub::Ptr Sub12::clone() const {
    return std::make_shared <Sub12> (*this);
}

}
}
}

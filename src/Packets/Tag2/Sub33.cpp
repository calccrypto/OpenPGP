#ifdef GPG_COMPATIBLE

#include "Packets/Tag2/Sub33.h"

namespace OpenPGP {
namespace Subpacket {
namespace Tag2 {

void Sub33::actual_read(const std::string & data){
    if (data.size()){
        set_version(data[0]);
        set_issuer_fingerprint(data.substr(1, size - 1));
    }
}

void Sub33::show_contents(HumanReadable & hr) const{
    hr << "Version: " + std::to_string(version) + "\n"
       << "Fingerprint: " + hexlify(issuer_fingerprint) + " (" + std::to_string(issuer_fingerprint.size()) + " octets)";
}

Sub33::Sub33()
    : Sub(ISSUER_FINGERPRINT),
      version(0),
      issuer_fingerprint()
{}

Sub33::Sub33(const std::string & data)
    : Sub33()
{
    read(data);
}

std::string Sub33::raw() const{
    return std::string(1, version) + issuer_fingerprint;
}

uint8_t Sub33::get_version() const{
    return version;
}

std::string Sub33::get_issuer_fingerprint() const{
    return issuer_fingerprint;
}

void Sub33::set_version(const uint8_t ver){
    version = ver;
}

void Sub33::set_issuer_fingerprint(const std::string & fingerprint){
    issuer_fingerprint = fingerprint;
}

Sub::Ptr Sub33::clone() const{
    return std::make_shared <Sub33> (*this);
}

}
}
}

#endif

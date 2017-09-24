#ifdef GPG_COMPATIBLE

#include "Tag2Sub33.h"

Tag2Sub33::Tag2Sub33()
    : Tag2Subpacket(Tag2Subpacket::ISSUER_FINGERPRINT),
      issuer_fingerprint()
{}

Tag2Sub33::Tag2Sub33(const std::string & data)
    : Tag2Sub33()
{
    read(data);
}

void Tag2Sub33::read(const std::string & data){
    if (data.size()){
        size = data.size();
        version = data[0];
        issuer_fingerprint = data.substr(1, size - 1);
    }
}

std::string Tag2Sub33::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "Version: " + std::to_string(version) + "\n" +
           indent + tab + "Fingerprint: " + hexlify(issuer_fingerprint) + " (" + std::to_string(issuer_fingerprint.size()) + " octets)";
}

std::string Tag2Sub33::raw() const{
    return std::string(1, version) + issuer_fingerprint;
}

uint8_t Tag2Sub33::get_version() const{
    return version;
}

std::string Tag2Sub33::get_issuer_fingerprint() const{
    return issuer_fingerprint;
}

void Tag2Sub33::set_version(const uint8_t ver){
    version = ver;
}

void Tag2Sub33::set_issuer_fingerprint(const std::string & fingerprint){
    issuer_fingerprint = fingerprint;
}

Tag2Subpacket::Ptr Tag2Sub33::clone() const{
    return std::make_shared <Tag2Sub33> (*this);
}

#endif
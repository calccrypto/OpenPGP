#include "Packets/Tag18.h"

#include "common/includes.h"

namespace OpenPGP {
namespace Packet {

std::string Tag18::show_title() const {
    return Tag::show_title() + Partial::show_title();
}

Tag18::Tag18(const PartialBodyLength & part)
    : Tag(SYM_ENCRYPTED_INTEGRITY_PROTECTED_DATA, 1),
      Partial(part),
      protected_data()
{}

Tag18::Tag18(const Tag18 & copy)
    : Tag(copy),
      Partial(copy),
      protected_data(copy.protected_data)
{}

Tag18::Tag18(const std::string & data)
    : Tag18()
{
    read(data);
}

void Tag18::read(const std::string & data){
    size = data.size();
    version = data[0];
    protected_data = data.substr(1, data.size() - 1);
}

std::string Tag18::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "Version: " + std::to_string(version) + "\n" +
           indent + tab + "Encrypted Data (" + std::to_string(protected_data.size()) + " octets): " + hexlify(protected_data);
}

std::string Tag18::raw() const{
    return std::string(1, version) + protected_data;
}

std::string Tag18::write() const{
    const std::string data = raw();
    if ((header_format == HeaderFormat::NEW) || // specified new header
        (tag > 15)){                            // tag > 15, so new header is required
        return write_new_length(tag, data, partial);
    }
    return write_old_length(tag, data, partial);
}

std::string Tag18::get_protected_data() const{
    return protected_data;
}

void Tag18::set_protected_data(const std::string & p){
    protected_data = p;
    size = raw().size();
}

Tag::Ptr Tag18::clone() const{
    return std::make_shared <Packet::Tag18> (*this);
}

Tag18 & Tag18::operator=(const Tag18 &copy){
    Tag::operator=(copy);
    Partial::operator=(copy);
    return *this;
}


}
}

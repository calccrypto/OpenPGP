#include "Packets/Tag9.h"

#include "common/includes.h"

namespace OpenPGP {
namespace Packet {

void Tag9::actual_read(const std::string & data){
    encrypted_data = data;
}

std::string Tag9::show_title() const {
    return Tag::show_title() + Partial::show_title();
}

Tag9::Tag9(const PartialBodyLength &part)
    : Tag(SYMMETRICALLY_ENCRYPTED_DATA),
      Partial(part),
      encrypted_data()
{}

Tag9::Tag9(const Tag9 & copy)
    : Tag(copy),
      Partial(copy),
      encrypted_data(copy.encrypted_data)
{}

Tag9::Tag9(const std::string & data)
    : Tag9()
{
    read(data);
}

std::string Tag9::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    return indent + show_title() + "\n" +
           indent + tab + "Encrypted Data (" + std::to_string(encrypted_data.size()) + " octets): " + hexlify(encrypted_data);
}

std::string Tag9::raw() const{
    return encrypted_data;
}

std::string Tag9::write() const{
    const std::string data = raw();
    if ((header_format == HeaderFormat::NEW) || // specified new header
        (tag > 15)){                            // tag > 15, so new header is required
        return write_new_length(tag, data, partial);
    }
    return write_old_length(tag, data, partial);
}

std::string Tag9::get_encrypted_data() const{
    return encrypted_data;
}

void Tag9::set_encrypted_data(const std::string & e){
    encrypted_data = e;
    size = raw().size();
}

Tag::Ptr Tag9::clone() const{
    return std::make_shared <Packet::Tag9> (*this);
}

Tag9 & Tag9::operator=(const Tag9 &copy){
    Tag::operator=(copy);
    Partial::operator=(copy);
    return *this;
}

}
}

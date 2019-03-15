#include "Packets/Tag8.h"

#include "Compress/Compress.h"
#include "Message.h"

namespace OpenPGP {
namespace Packet {

std::string Tag8::compress(const std::string & data) const{
    return Compression::compress(comp, data);
}

std::string Tag8::decompress(const std::string & data) const{
    return Compression::decompress(comp, data);
}

void Tag8::actual_read(const std::string & data){
    if (size) {
        comp = data[0]; // don't call set_comp here to prevent decompressing and recompressing old data
        set_compressed_data(data.substr(1, size - 1));
    }
}

std::string Tag8::show_title() const {
    return Tag::show_title() + Partial::show_title();
}

void Tag8::show_contents(HumanReadable & hr) const{
    const decltype(Compression::NAME)::const_iterator comp_it = Compression::NAME.find(comp);
    Message decompressed;
    decompressed.read_raw(get_data());

    hr << "Compression Algorithm: " + ((comp_it == Compression::NAME.end())?"Unknown":(comp_it -> second)) + " (compress " + std::to_string(comp) + ")"
       << "Compressed Data:"
       << HumanReadable::DOWN;
    decompressed.show(hr);
    hr << HumanReadable::UP;
}

Tag8::Tag8(const PartialBodyLength & part)
    : Tag(COMPRESSED_DATA, 3),
      Partial(part),
      comp(Compression::ID::UNCOMPRESSED),
      compressed_data()
{}

Tag8::Tag8(const std::string & data)
    : Tag8()
{
    read(data);
}

std::string Tag8::raw() const{
    return std::string(1, comp) + compressed_data;
}

std::string Tag8::write() const{
    const std::string data = raw();
    if ((header_format == HeaderFormat::NEW) || // specified new header
        (tag > 15)){                            // tag > 15, so new header is required
        return write_new_length(tag, data, partial);
    }
    return write_old_length(tag, data, partial);
}

uint8_t Tag8::get_comp() const{
    return comp;
}

std::string Tag8::get_data() const{
    return decompress(compressed_data);
}

Message Tag8::get_body() const {
    Message msg;
    msg.read_raw(get_data());           // "A Compressed Data Packet’s body contains an block that compresses some set of packets."
    return msg;
}

std::string Tag8::get_compressed_data() const{
    return compressed_data;
}

void Tag8::set_comp(const uint8_t alg){
    // recompress data
    const std::string data = get_data();// decompress data
    comp = alg;                         // set new compression algorithm
    set_data(data);                     // compress data with new algorithm
    comp = alg;
}

void Tag8::set_data(const std::string & data){
    compressed_data = compress(data);
}

void Tag8::set_body(const Message & msg) {
    // set the decompressed data to the raw packets of the message
    set_data(msg.raw());
}

void Tag8::set_compressed_data(const std::string & data){
    compressed_data = data;
}

Tag::Ptr Tag8::clone() const{
    return std::make_shared <Packet::Tag8> (*this);
}

}
}

#include "Tag8.h"
#include "../Message.h"

namespace OpenPGP {
namespace Packet {

std::string Tag8::compress(const std::string & data) const{
    return Compression::compress(comp, data);
}

std::string Tag8::decompress(const std::string & data) const{
    return Compression::decompress(comp, data);
}

std::string Tag8::show_title() const{
    std::string out = std::string(format?"New":"Old") + ": " + NAME.at(8) + " (Tag 8)";   // display packet name and tag number

    switch (partial){
        case 0:
            break;
        case 1:
            out += " (partial start)";
            break;
        case 2:
            out += " (partial continue)";
            break;
        case 3:
            out += " (partial end)";
            break;
        default:
            throw std::runtime_error("Error: Unknown partial type: " + std::to_string(partial));
            break;
    }

    return out;
}

Tag8::Tag8()
    : Tag(COMPRESSED_DATA, 3),
      comp(Compression::ID::UNCOMPRESSED),
      compressed_data()
{}

Tag8::Tag8(const Tag8 & copy)
    : Tag(copy),
      comp(copy.comp),
      compressed_data(copy.compressed_data)
{}

Tag8::Tag8(const std::string & data)
    : Tag8()
{
    read(data);
}

void Tag8::read(const std::string & data){
    size = data.size();
    comp = data[0];
    compressed_data = data.substr(1, size - 1);
}

std::string Tag8::show(const std::size_t indents, const std::size_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');
    const decltype(Compression::NAME)::const_iterator comp_it = Compression::NAME.find(comp);
    Message decompressed;
    decompressed.read_raw(get_data()); // do this in case decompressed data contains headers

    return indent + show_title() + "\n" +
           indent + tab + "Compression Algorithm: " + ((comp_it == Compression::NAME.end())?"Unknown":(comp_it -> second)) + " (compress " + std::to_string(comp) + ")\n" +
           indent + tab + "Compressed Data:\n" +
           decompressed.show(indents + 2, indent_size);
}

std::string Tag8::raw() const{
    return std::string(1, comp) + compressed_data;
}

uint8_t Tag8::get_comp() const{
    return comp;
}

std::string Tag8::get_compressed_data() const{
    return compressed_data;
}

std::string Tag8::get_data() const{
    return decompress(compressed_data);
}

void Tag8::set_comp(const uint8_t alg){
    // recompress data
    const std::string data = get_data();// decompress data
    comp = alg;                         // set new compression algorithm
    set_data(data);                     // compress data with new algorithm
    comp = alg;
    size = raw().size();
}

void Tag8::set_data(const std::string & data){
    compressed_data = compress(data);
    size = raw().size();
}

void Tag8::set_compressed_data(const std::string & data){
    compressed_data = data;
    size = raw().size();
}

Tag::Ptr Tag8::clone() const{
    return std::make_shared <Packet::Tag8> (*this);
}

}
}
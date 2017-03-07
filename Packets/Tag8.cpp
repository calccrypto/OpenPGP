#include "Tag8.h"
#include "../PGPMessage.h"

std::string Tag8::compress(const std::string & data){
    return PGP_compress(comp, data);
}

std::string Tag8::decompress(const std::string & data){
    return PGP_decompress(comp, data);
}

std::string Tag8::show_title() const{
    std::string out = std::string(format?"New":"Old") + ": " + Packet::NAME.at(8) + " (Tag 8)";   // display packet name and tag number

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
    : Packet(Packet::COMPRESSED_DATA, 3),
      comp(Compression::Algorithm::UNCOMPRESSED),
      compressed_data()
{}

Tag8::Tag8(const Tag8 & copy)
    : Packet(copy),
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

std::string Tag8::show(const uint8_t indents, const uint8_t indent_size) const{
    const std::string indent(indents * indent_size, ' ');
    const std::string tab(indent_size, ' ');

    PGPMessage decompressed;
    decompressed.read_raw(get_data()); // do this in case decompressed data contains headers

    return indent + show_title() + "\n" +
           indent + tab + "Compression Algorithm: " + Compression::Name.at(comp) + " (compress " + std::to_string(comp) + ")\n" +
           indent + tab + "Compressed Data:\n" +
           decompressed.show(indents + 1, indent_size);
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
    return PGP_decompress(comp, compressed_data);
}

void Tag8::set_comp(const uint8_t alg){
    // recompress data
    if (compressed_data.size()){
        const std::string data = get_data();// decompress data
        comp = alg;                         // set new compression algorithm
        set_data(data);                     // compress data with new algorithm
    }

    comp = alg;

    size = raw().size();
}

void Tag8::set_data(const std::string & data){
    compressed_data = PGP_compress(comp, data);
    size = raw().size();
}

void Tag8::set_compressed_data(const std::string & data){
    compressed_data = data;
    size = raw().size();
}

Packet::Ptr Tag8::clone() const{
    return std::make_shared <Tag8> (*this);
}

#include "Tag8.h"
#include "../PGPMessage.h"

std::string Tag8::compress(const std::string & data){
    return PGP_compress(comp, data);
}

std::string Tag8::decompress(const std::string & data){
    return PGP_decompress(comp, data);
}

std::string Tag8::show_title() const{
    std::stringstream out;
    out << (format?"New":"Old") << ": " << Packet_Tags.at(8) << " (Tag 8)";   // display packet name and tag number

    switch (partial){
        case 0:
            break;
        case 1:
            out << " (partial start)";
            break;
        case 2:
            out << " (partial continue)";
            break;
        case 3:
            out << " (partial end)";
            break;
        default:
            {
                std::stringstream s; s << static_cast <unsigned int> (partial);
                throw std::runtime_error("Error: Unknown partial type: " + s.str());
            }
            break;
    }
    return out.str();
}

Tag8::Tag8():
    Packet(8, 3),
    comp(0),
    compressed_data()
{}

Tag8::Tag8(std::string & data):
    Tag8()
{
    read(data);
}

void Tag8::read(std::string & data, const uint8_t part){
    size = data.size();
    comp = data[0];
    compressed_data = data.substr(1, data.size() - 1);
}

std::string Tag8::show(const uint8_t indents, const uint8_t indent_size) const{
    unsigned int tab = indents * indent_size;
    std::string data = get_data();
    PGPMessage decompressed;
    decompressed.read_raw(data); // do this in case decompressed data contains headers
    std::stringstream out;
    out << std::string(tab, ' ') << show_title() << "\n"
        << std::string(tab, ' ') << "    Compression algorithm: " << Compression_Algorithms.at(comp) << "(compress " << static_cast <unsigned int> (comp) << ")\n"
        << std::string(tab, ' ') << "Compressed Data:\n"
        << decompressed.show(indents + 1, indent_size);
    return out.str();
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

void Tag8::set_comp(const uint8_t c){
    // recompress data
    if (compressed_data.size()){
        std::string data = get_data(); // decompress data
        comp = c;                      // set new compression algorithm
        set_data(data);                // compress data with new algorithm
    }

    comp = c;

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

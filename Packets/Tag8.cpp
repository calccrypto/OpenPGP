#include "Tag8.h"

std::string Tag8::compress(const std::string & data){
    return PGP_compress(comp, data);
}

std::string Tag8::decompress(const std::string & data){
    return PGP_decompress(comp, data);
}

Tag8::Tag8() :
    Packet(8, 3),
    comp(0),
    compressed_data()
{
}

Tag8::Tag8(std::string & data) :
    Tag8()
{
    read(data);
}

void Tag8::read(std::string & data){
    size = data.size();
    comp = data[0];
    compressed_data = data.substr(1, data.size() - 1);
}

std::string Tag8::show() const{
    std::string data = get_data();
    std::stringstream out;
    out << "    Compression algorithm: " << Compression_Algorithms.at(comp) << "(compress " << static_cast <unsigned int> (comp) << ")\n"
        << "    Data in hex (" << compressed_data.size() << " octets): " << hexlify(compressed_data) << "\n";
        //<< PGPMessage(data).show() << std::endl;
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
    return Ptr(new Tag8(*this));
}

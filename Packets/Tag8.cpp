#include "Tag8.h"

std::string Tag8::compress(std::string data){
    std::string out = "";
    switch (comp){
        case 0: // Uncompressed
            out = data;
            break;
        case 100: case 101: case 102: case 103: case 104: case 105: case 106: case 107: case 108: case 109: case 110:
            throw std::runtime_error("Error: Private/Experimental algorithm.");
        case 1: // ZIP [RFC1951]
        case 2: // ZLIB [RFC1950]
        case 3: // BZip2 [BZ2]
        default:
            throw std::runtime_error("Error: Compression functions not implemented.");
                        break;
    }
    return out;
}

std::string Tag8::decompress(std::string data){
    std::string out = "";
    switch (comp){
        case 0: // Uncompressed
            out = data;
            break;
        case 100: case 101: case 102: case 103: case 104: case 105: case 106: case 107: case 108: case 109: case 110:
            throw std::runtime_error("Error: Private/Experimental algorithm.");
        case 1: // ZIP [RFC1951]
        case 2: // ZLIB [RFC1950]
        case 3: // BZip2 [BZ2]
        default:
            throw std::runtime_error("Error: Decompression functions not implemented.");
                        break;
    }
    return out;
}

Tag8::Tag8(){
    tag = 8;
    version = 3;
    comp = 0;
}

Tag8::Tag8(std::string & data){
    tag = 8;
    read(data);
}

void Tag8::read(std::string & data){
    size = data.size();
    comp = data[0];
    compressed_data = data.substr(1, data.size() - 1);
}

std::string Tag8::show(){
    std::stringstream out;
    out << "    Compression Algorithm: " << Compression_Algorithms.at(comp) << "(compress " << (unsigned int) comp << ")\n"
        << "    Data in hex (" << compressed_data.size() << " octets): " << hexlify(compressed_data) << "\n";
    return out.str();
}

std::string Tag8::raw(){
    return std::string(1, comp) + compressed_data;
}

uint8_t Tag8::get_comp(){
    return comp;
}

std::string Tag8::get_compressed_data(){
    return compressed_data;
}

std::string Tag8::get_data(){
    return "Data in hex, so it's easier to copy to a " + Compression_Algorithms.at(comp) + " decompressor:\n\n" + hexlify(compressed_data);
//    return decompress(compressed_data);
}

void Tag8::set_comp(const uint8_t c){
    comp = c;
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

Tag8 * Tag8::clone(){
    return new Tag8(*this);
}

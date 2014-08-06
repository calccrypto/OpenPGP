#include "Compress.h"

std::string compress(const uint8_t alg, const std::string & data){
    if (alg){ // if the algorithm value is not zero
        // create both files; forced to use FILE * to use compression algorithms
        FILE * src = fopen("srctmp", "a+b");
        FILE * dst = fopen("dsttmp", "a+b");
        bool good = true;
        
        // write data to source file
        fwrite(data.c_str(), sizeof(char), data.size(), src);
        
        switch (alg){
            case 1: // ZIP [RFC1951]
                break;
            case 2: // ZLIB[RFC1950]
                good = (def(src, dst, Z_DEFAULT_COMPRESSION) == Z_OK);
                break;
            case 3: // BZip2 [BZ2]
                good = (bz2_compress(src, dst) == BZ_OK);
                break;
            default:
                {
                    std::stringstream tmp; tmp << (int) alg;
                    throw std::runtime_error("Error: Unknown Compression Algorithm value: " + tmp.str());
                }
                break;
        }
        
        if (!good){
            throw std::runtime_error("Error: Ccompression failed");
        }
        
        fclose(src);
        fclose(dst);
        remove("srctmp");
        
        std::ifstream compressed("dsttmp", std::ios::binary);
        std::stringstream buf;
        buf << compressed.rdbuf();
        
        compressed.close();
        remove("dsttmp");
        
        return buf.str();
    }
    return data; // 0: Uncompressed
}

std::string decompress(const uint8_t alg, const std::string & data){
    if (alg){ // if the algorithm value is not zero
        // create both files; forced to use FILE * to use compression algorithms
        FILE * src = fopen("srctmp", "a+b");
        FILE * dst = fopen("dsttmp", "a+b");
        bool good = true;
        
        // write data to source file
        fwrite(data.c_str(), sizeof(char), data.size(), src);
        
        switch (alg){
            case 1: // ZIP [RFC1951]
                break;
            case 2: // ZLIB[RFC1950]
                good = (inf(src, dst) == Z_OK);
                break;
            case 3: // BZip2 [BZ2]
                good = (bz2_decompress(src, dst) == BZ_OK);
                break;
            default:
                {
                    std::stringstream tmp; tmp << (int) alg;
                    throw std::runtime_error("Error: Unknown Compression Algorithm value: " + tmp.str());
                }
                break;
        }
        
        if (!good){
            throw std::runtime_error("Error: Ccompression failed");
        }
        
        fclose(src);
        fclose(dst);
        remove("srctmp");
        
        std::ifstream compressed("dsttmp", std::ios::binary);
        std::stringstream buf;
        buf << compressed.rdbuf();
        
        compressed.close();
        remove("dsttmp");
        
        return buf.str();
    }
    return data; // 0: Uncompressed
}
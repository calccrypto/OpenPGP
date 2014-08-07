#include "Compress.h"

std::string PGP_compress(const uint8_t alg, const std::string & data){
    if (alg){ // if the algorithm value is not zero
        // // create both files; forced to use FILE * to use compression algorithms
        // FILE * src = fopen("srctmp", "a+b");
        // FILE * dst = fopen("dsttmp", "a+b");
         bool good = false;
        std::string out;

        // // write data to source file
        // fwrite(data.c_str(), sizeof(char), data.size(), src);

        switch (alg){
            case 1: // ZIP [RFC1951]
                good = (zlib_compress(data, out, DEFLATE_WINDOWBITS, Z_DEFAULT_COMPRESSION) == Z_OK);
                break;
            case 2: // ZLIB[RFC1950]
                good = (zlib_compress(data, out, ZLIB_WINDOWBITS, Z_DEFAULT_COMPRESSION) == Z_OK);
                break;
            case 3: // BZip2 [BZ2]
                // good = (bz2_compress(src, dst) == BZ_OK);
                break;
            default:
                {
                    std::stringstream tmp; tmp << (int) alg;
                    throw std::runtime_error("Error: Unknown Compression Algorithm value: " + tmp.str());
                }
                break;
        }

        if (!good){
            throw std::runtime_error("Error: Compression failed");
        }

        // fclose(src);
        // fclose(dst);
        // remove("srctmp");

        // std::ifstream compressed("dsttmp", std::ios::binary);
        // std::stringstream buf;
        // buf << compressed.rdbuf();

        // compressed.close();
        // remove("dsttmp");

        // return buf.str();
        return out;
    }
    return data; // 0: Uncompressed
}

std::string PGP_decompress(const uint8_t alg, const std::string & data){
    if (alg){ // if the algorithm value is not zero
        bool good = false;
        std::string out;
        switch (alg){
            case 1: // ZIP [RFC1951]
                good = (zlib_decompress(data, out, DEFLATE_WINDOWBITS) == Z_OK);
                break;
            case 2: // ZLIB[RFC1950]
                good = (zlib_decompress(data, out, ZLIB_WINDOWBITS) == Z_OK);
                break;
            case 3: // BZip2 [BZ2]
                // good = (bz2_decompress(data, out) == BZ_OK);
                break;
            default:
                {
                    std::stringstream tmp; tmp << (int) alg;
                    throw std::runtime_error("Error: Unknown Compression Algorithm value: " + tmp.str());
                }
                break;
        }

        if (!good){
            throw std::runtime_error("Error: Decompression failed");
        }
        
        return out;
    }
    return data; // 0: Uncompressed
}
#include "Compress.h"

std::string PGP_compress(const uint8_t alg, const std::string & src){
    if (alg && src.size()){ // if the algorithm value is not zero and there is data
        bool good = false;
        std::string dst;

        switch (alg){
            case 1: // ZIP [RFC1951]
                good = (zlib_compress(src, dst, DEFLATE_WINDOWBITS, Z_DEFAULT_COMPRESSION) == Z_OK);
                break;
            case 2: // ZLIB[RFC1950]
                good = (zlib_compress(src, dst, ZLIB_WINDOWBITS, Z_DEFAULT_COMPRESSION) == Z_OK);
                break;
            case 3: // BZip2 [BZ2]
                good = (bz2_compress(src, dst) == BZ_OK);
                break;
            default:
                {
                    std::stringstream tmp; tmp << static_cast <unsigned int> (alg);
                    throw std::runtime_error("Error: Unknown or undefined compression algorithm value: " + tmp.str());
                }
                break;
        }

        if (!good){
            throw std::runtime_error("Error: Compression failed");
        }

        return dst;
    }
    return src; // 0: Uncompressed
}

std::string PGP_decompress(const uint8_t alg, const std::string & src){
    if (alg && src.size()){ // if the algorithm value is not zero and there is data
        bool good = false;
        std::string dst;
        switch (alg){
            case 1: // ZIP [RFC1951]
                good = (zlib_decompress(src, dst, DEFLATE_WINDOWBITS) == Z_OK);
                break;
            case 2: // ZLIB[RFC1950]
                good = (zlib_decompress(src, dst, ZLIB_WINDOWBITS) == Z_OK);
                break;
            case 3: // BZip2 [BZ2]
                good = (bz2_decompress(src, dst) == BZ_OK);
                break;
            default:
                {
                    std::stringstream tmp; tmp << static_cast <unsigned int> (alg);
                    throw std::runtime_error("Error: Unknown Compression Algorithm value: " + tmp.str());
                }
                break;
        }

        if (!good){
            throw std::runtime_error("Error: Decompression failed");
        }

        return dst;
    }
    return src; // 0: Uncompressed
}
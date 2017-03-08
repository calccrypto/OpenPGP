#include "Compress.h"

std::string PGP_compress(const uint8_t alg, const std::string & src){
    if ((alg != Compression::UNCOMPRESSED) && src.size()){ // if the algorithm value is not zero and there is data
        bool good = false;
        std::string dst;

        switch (alg){
            case Compression::ZIP:
                good = (zlib_compress(src, dst, DEFLATE_WINDOWBITS, Z_DEFAULT_COMPRESSION) == Z_OK);
                break;
            case Compression::ZLIB:
                good = (zlib_compress(src, dst, ZLIB_WINDOWBITS, Z_DEFAULT_COMPRESSION) == Z_OK);
                break;
            case Compression::BZIP2:
                good = (bz2_compress(src, dst) == BZ_OK);
                break;
            default:
                throw std::runtime_error("Error: Unknown or undefined compression algorithm value: " + std::to_string(alg));
                break;
        }

        if (!good){
            throw std::runtime_error("Error: Compression failed");
        }

        return dst;
    }
    return src; // 0: uncompressed
}

std::string PGP_decompress(const uint8_t alg, const std::string & src){
    if ((alg != Compression::UNCOMPRESSED) && src.size()){ // if the algorithm value is not zero and there is data
        bool good = false;
        std::string dst;
        switch (alg){
            case Compression::ZIP:
                good = (zlib_decompress(src, dst, DEFLATE_WINDOWBITS) == Z_OK);
                break;
            case Compression::ZLIB:
                good = (zlib_decompress(src, dst, ZLIB_WINDOWBITS) == Z_OK);
                break;
            case Compression::BZIP2:
                good = (bz2_decompress(src, dst) == BZ_OK);
                break;
            default:
                throw std::runtime_error("Error: Unknown Compression Algorithm value: " + std::to_string(alg));
                break;
        }

        if (!good){
            throw std::runtime_error("Error: Decompression failed");
        }

        return dst;
    }
    return src; // 0: uncompressed
}
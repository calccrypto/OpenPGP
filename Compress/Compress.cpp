#include "Compress.h"

namespace OpenPGP {
namespace Compression {

std::string compress(const uint8_t alg, const std::string & src){
    if ((alg != ID::UNCOMPRESSED) && src.size()){ // if the algorithm value is not zero and there is data
        bool good = false;
        std::string dst;

        switch (alg){
            case ID::ZIP:
                good = (zlib_compress(src, dst, DEFLATE_WINDOWBITS, Z_DEFAULT_COMPRESSION) == Z_OK);
                break;
            case ID::ZLIB:
                good = (zlib_compress(src, dst, ZLIB_WINDOWBITS, Z_DEFAULT_COMPRESSION) == Z_OK);
                break;
            case ID::BZIP2:
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

std::string decompress(const uint8_t alg, const std::string & src){
    if ((alg != ID::UNCOMPRESSED) && src.size()){ // if the algorithm value is not zero and there is data
        bool good = false;
        std::string dst;
        switch (alg){
            case ID::ZIP:
                good = (zlib_decompress(src, dst, DEFLATE_WINDOWBITS) == Z_OK);
                break;
            case ID::ZLIB:
                good = (zlib_decompress(src, dst, ZLIB_WINDOWBITS) == Z_OK);
                break;
            case ID::BZIP2:
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

}
}
